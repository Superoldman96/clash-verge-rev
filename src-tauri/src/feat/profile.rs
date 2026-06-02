use crate::{
    cmd,
    config::{
        Config, PrfItem, PrfOption,
        profiles::{profiles_draft_update_item_safe, profiles_set_cvd_pub_safe},
    },
    core::{CoreManager, handle, tray, validate::ValidationOutcome},
    utils::help::{mask_err, mask_url},
};
use anyhow::{Result, bail};
use clash_verge_logging::{Type, logging, logging_error};
use smartstring::alias::String;
use tauri::Emitter as _;

/// Toggle proxy profile
pub async fn toggle_proxy_profile(profile_index: String) {
    logging_error!(
        Type::Config,
        cmd::patch_profiles_config_by_profile_index(profile_index).await
    );
}

pub async fn switch_proxy_node(group_name: &str, proxy_name: &str) {
    match handle::Handle::mihomo()
        .await
        .select_node_for_group(group_name, proxy_name)
        .await
    {
        Ok(_) => {
            logging!(info, Type::Tray, "切换代理成功: {} -> {}", group_name, proxy_name);
            let _ = handle::Handle::app_handle().emit("verge://refresh-proxy-config", ());
            let _ = tray::Tray::global().update_menu().await;
            return;
        }
        Err(err) => {
            logging!(
                error,
                Type::Tray,
                "切换代理失败: {} -> {}, 错误: {:?}",
                group_name,
                proxy_name,
                err
            );
        }
    }

    match handle::Handle::mihomo()
        .await
        .select_node_for_group(group_name, proxy_name)
        .await
    {
        Ok(_) => {
            logging!(info, Type::Tray, "代理切换回退成功: {} -> {}", group_name, proxy_name);
            let _ = tray::Tray::global().update_menu().await;
        }
        Err(err) => {
            logging!(
                error,
                Type::Tray,
                "代理切换最终失败: {} -> {}, 错误: {:?}",
                group_name,
                proxy_name,
                err
            );
        }
    }
}

async fn should_update_profile(uid: &String, ignore_auto_update: bool) -> Result<Option<(String, Option<PrfOption>)>> {
    let profiles = Config::profiles().await;
    let profiles = profiles.latest_arc();
    let item = profiles.get_item(uid)?;
    let is_remote = item.itype.as_ref().is_some_and(|s| s == "remote");

    if !is_remote {
        logging!(info, Type::Config, "[订阅更新] {uid} 不是远程订阅，跳过更新");
        Ok(None)
    } else if item.url.is_none() {
        logging!(warn, Type::Config, "Warning: [订阅更新] {uid} 缺少URL，无法更新");
        bail!("failed to get the profile item url");
    } else if !ignore_auto_update && !item.option.as_ref().and_then(|o| o.allow_auto_update).unwrap_or(true) {
        logging!(info, Type::Config, "[订阅更新] {} 禁止自动更新，跳过更新", uid);
        Ok(None)
    } else {
        logging!(
            info,
            Type::Config,
            "[订阅更新] {} 是远程订阅，URL: {}",
            uid,
            mask_url(
                item.url
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Profile URL is None"))?
            )
        );
        Ok(Some((
            item.url.clone().ok_or_else(|| anyhow::anyhow!("Profile URL is None"))?,
            item.option.clone(),
        )))
    }
}

/// Persist a freshly-created CVD device key after a successful update (write-key-last), but ONLY if
/// CVD actually engaged this fetch — i.e. the built item cached a public key because the server
/// returned ciphertext. A plaintext airport leaves `cvd_pub` None, so we never write the keychain
/// (which on macOS would pop a password prompt for a key the server isn't even using). Best-effort:
/// a failed write just means the key self-heals on the next ciphertext.
fn persist_cvd_key(item: &PrfItem, key: Option<&crate::cvd::DeviceKey>) {
    if item.cvd_pub.is_some()
        && let Some(key) = key
        && let Err(e) = key.persist()
    {
        logging!(
            warn,
            Type::Config,
            "cvd: failed to persist device key after update: {e}"
        );
    }
}

/// On a missing-private-key error from a refresh (the device was restored, or an earlier `persist`
/// failed), re-register: mint a fresh key, store it, and repoint the profile's cached public key so
/// the NEXT refresh registers it with the airport and decrypts. If the keychain itself is
/// unavailable, clear the cached pubkey instead — the profile goes dormant until a later manual
/// update re-creates it (so we never loop, minting a new server slot each retry).
///
/// Returns `Some(message)` if it handled a key-missing error (the caller must stop retrying: this
/// response was sealed to the lost key and can't be read), or `None` for any other error.
///
/// No orphan risk: the key is written for a profile that already exists — there is no `append` that
/// could fail and strand it.
async fn try_cvd_reregister(uid: &String, err: &anyhow::Error) -> Option<std::string::String> {
    // Only handle the missing-key signal; any other error → None (caller keeps retrying).
    err.downcast_ref::<crate::cvd::CvdKeyMissing>()?;
    let newkey = crate::cvd::DeviceKey::generate(uid);

    // ORDER MATTERS: record the new public key BEFORE writing the private key. If we persisted first
    // and the cvd_pub write then failed, the keychain would hold the NEW private key while
    // profiles.yaml still advertised the OLD public key. The server would seal to OLD, we'd hold only
    // NEW, and decryption would fail as a plain *error* (not "key missing") — so recovery would never
    // re-trigger and the profile would be stuck forever. Writing cvd_pub first means every failure
    // below leaves a self-healing "key missing" state (no private key for the advertised pubkey).
    if let Err(e) = profiles_set_cvd_pub_safe(uid.as_str(), Some(newkey.public_b64().into())).await {
        // Could not record the new pubkey → leave the existing missing-key state untouched; it
        // self-heals on the next refresh (cvd_pub still points at a key we don't have → CvdKeyMissing).
        logging!(
            warn,
            Type::Config,
            "[CVD] could not record re-registered pubkey for {uid}: {e}; will retry next refresh"
        );
        return Some(clash_verge_i18n::t!("errors.cvdKeyMissing").into_owned());
    }

    // cvd_pub now references the new key; persist the matching private key.
    match newkey.persist() {
        Ok(()) => {
            logging!(
                info,
                Type::Config,
                "[CVD] re-registered device key for {uid}; next refresh will sync"
            );
            Some(clash_verge_i18n::t!("errors.cvdKeyReregistered").into_owned())
        }
        Err(e) => {
            // Keychain unavailable/denied → drop the cvd_pub claim so the profile goes dormant instead
            // of re-minting (and burning a server slot) on every refresh. Best-effort: if this clear
            // also fails the state is still "key missing" (self-healing), never the stuck mismatch.
            let _ = profiles_set_cvd_pub_safe(uid.as_str(), None).await;
            logging!(
                warn,
                Type::Config,
                "[CVD] re-register failed (keychain unavailable) for {uid}: {e}"
            );
            Some(clash_verge_i18n::t!("errors.cvdKeyMissing").into_owned())
        }
    }
}

async fn perform_profile_update(
    uid: &String,
    url: &String,
    opt: Option<&PrfOption>,
    option: Option<&PrfOption>,
    is_mannual_trigger: bool,
) -> Result<bool> {
    logging!(info, Type::Config, "[订阅更新] 开始下载新的订阅内容");
    let mut merged_opt = PrfOption::merge(opt, option);
    let is_current = {
        let profiles = Config::profiles().await;
        profiles.latest_arc().is_current_profile_index(uid)
    };
    let profiles = Config::profiles().await;
    let profiles_arc = profiles.latest_arc();
    let profile_name = profiles_arc
        .get_name_by_uid(uid)
        .cloned()
        .unwrap_or_else(|| String::from("UnKnown Profile"));

    // Decide how this refresh uses CVD. A profile that already cached its public key refreshes with
    // it WITHOUT touching the keychain (so silent auto-updates never prompt on macOS); the private
    // key is read lazily, only if the server actually returns ciphertext. A pre-CVD profile (no
    // cached key) gets a new key only on a MANUAL update — a silent auto-update stays plaintext so
    // it can never trigger a keychain prompt. All three proxy retries share one key → one slot.
    let cvd_pub_cached = profiles_arc
        .get_item(uid.as_str())
        .ok()
        .and_then(|it| it.cvd_pub.as_deref().and_then(crate::cvd::public_from_b64));
    let new_key = if cvd_pub_cached.is_none() && is_mannual_trigger {
        Some(crate::cvd::DeviceKey::generate(uid))
    } else {
        None
    };
    let cvd_mode = match (cvd_pub_cached, new_key.as_ref()) {
        (Some(public), _) => crate::cvd::CvdMode::Existing { public },
        (None, Some(key)) => crate::cvd::CvdMode::New(key),
        (None, None) => crate::cvd::CvdMode::Disabled,
    };

    let mut last_err;

    match PrfItem::from_url(url, None, None, merged_opt.as_ref(), uid.as_str(), cvd_mode).await {
        Ok(mut item) => {
            logging!(info, Type::Config, "[订阅更新] 更新订阅配置成功");
            profiles_draft_update_item_safe(uid, &mut item).await?;
            persist_cvd_key(&item, new_key.as_ref());
            return Ok(is_current);
        }
        Err(err) => {
            if let Some(msg) = try_cvd_reregister(uid, &err).await {
                bail!("{msg}");
            }
            logging!(
                warn,
                Type::Config,
                "Warning: [订阅更新] 正常更新失败: {}，尝试使用Clash代理更新",
                mask_err(&err.to_string())
            );
            last_err = err;
        }
    }

    merged_opt.get_or_insert_with(PrfOption::default).self_proxy = Some(true);
    merged_opt.get_or_insert_with(PrfOption::default).with_proxy = Some(false);

    match PrfItem::from_url(url, None, None, merged_opt.as_ref(), uid.as_str(), cvd_mode).await {
        Ok(mut item) => {
            logging!(info, Type::Config, "[订阅更新] 使用 Clash代理 更新订阅配置成功");
            profiles_draft_update_item_safe(uid, &mut item).await?;
            persist_cvd_key(&item, new_key.as_ref());
            handle::Handle::notice_message("update_with_clash_proxy", profile_name);
            drop(last_err);
            return Ok(is_current);
        }
        Err(err) => {
            if let Some(msg) = try_cvd_reregister(uid, &err).await {
                bail!("{msg}");
            }
            logging!(
                warn,
                Type::Config,
                "Warning: [订阅更新] Clash代理更新失败: {}，尝试使用系统代理更新",
                mask_err(&err.to_string())
            );
            last_err = err;
        }
    }

    merged_opt.get_or_insert_with(PrfOption::default).self_proxy = Some(false);
    merged_opt.get_or_insert_with(PrfOption::default).with_proxy = Some(true);

    match PrfItem::from_url(url, None, None, merged_opt.as_ref(), uid.as_str(), cvd_mode).await {
        Ok(mut item) => {
            logging!(info, Type::Config, "[订阅更新] 使用 系统代理 更新订阅配置成功");
            profiles_draft_update_item_safe(uid, &mut item).await?;
            persist_cvd_key(&item, new_key.as_ref());
            handle::Handle::notice_message("update_with_clash_proxy", profile_name);
            drop(last_err);
            return Ok(is_current);
        }
        Err(err) => {
            if let Some(msg) = try_cvd_reregister(uid, &err).await {
                bail!("{msg}");
            }
            logging!(
                warn,
                Type::Config,
                "Warning: [订阅更新] 系统代理更新失败: {}，所有重试均已失败",
                mask_err(&err.to_string())
            );
            last_err = err;
        }
    }

    if is_mannual_trigger {
        handle::Handle::notice_message("update_failed_even_with_clash", format!("{profile_name} - {last_err}"));
    }
    Ok(is_current)
}

pub async fn update_profile(
    uid: &String,
    option: Option<&PrfOption>,
    auto_refresh: bool,
    ignore_auto_update: bool,
    is_mannual_trigger: bool,
) -> Result<()> {
    logging!(info, Type::Config, "[订阅更新] 开始更新订阅 {}", uid);
    let url_opt = should_update_profile(uid, ignore_auto_update).await?;

    let should_refresh = match url_opt {
        Some((url, opt)) => {
            perform_profile_update(uid, &url, opt.as_ref(), option, is_mannual_trigger).await? && auto_refresh
        }
        None => auto_refresh,
    };

    if should_refresh {
        logging!(info, Type::Config, "[订阅更新] 更新内核配置");
        match CoreManager::global().update_config_with_force(is_mannual_trigger).await {
            Ok(outcome) if outcome.is_valid() => {
                logging!(info, Type::Config, "[订阅更新] 更新成功");
                handle::Handle::refresh_clash();
            }
            Ok(outcome @ (ValidationOutcome::Skipped { .. } | ValidationOutcome::Busy)) if !is_mannual_trigger => {
                logging!(info, Type::Config, "[订阅更新] 本次配置刷新已跳过: {}", outcome);
            }
            Ok(outcome) => {
                let message = outcome.to_string();
                logging!(error, Type::Config, "[订阅更新] 更新失败: {}", message);
                handle::Handle::notice_message("update_failed", message);
            }
            Err(err) => {
                logging!(error, Type::Config, "[订阅更新] 更新失败: {}", err);
                handle::Handle::notice_message("update_failed", format!("{err}"));
                logging!(error, Type::Config, "{err}");
            }
        }
    }

    Ok(())
}

/// 增强配置
pub async fn enhance_profiles() -> Result<ValidationOutcome> {
    CoreManager::global().update_config_forced().await
}
