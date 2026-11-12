//! The languages of the HTML pages: English and Chinese (simplified).
//!
//! The language of a page follows the browser's `Accept-Language` ([`Lang::from_headers`]).
//! Every string a page shows is a field of [`Text`]; `texts!` defines each one in both
//! languages on one line, so a translation can never be missing. Strings with values use
//! `{}` placeholders, filled in order by [`fill`]. The admin UI is English only for now.

use axum::http::{HeaderMap, header};

/// A page language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    /// English (the default).
    #[default]
    En,
    /// Chinese, simplified script.
    Zh,
}

impl Lang {
    /// The language the browser prefers among the supported ones: the first `zh*` or `en*`
    /// tag in `Accept-Language`, by quality and then by order; English otherwise.
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let Some(value) = headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|value| value.to_str().ok())
        else {
            return Self::En;
        };
        let mut ranges: Vec<(u16, usize, &str)> = value
            .split(',')
            .enumerate()
            .filter_map(|(index, item)| {
                let mut parts = item.split(';');
                let tag = parts.next()?.trim();
                let quality = parts
                    .filter_map(|param| param.trim().strip_prefix("q="))
                    .find_map(|q| q.trim().parse::<f32>().ok())
                    .unwrap_or(1.0);
                // Thousandths, so that the sort needs no float comparison.
                let quality = (quality.clamp(0.0, 1.0) * 1000.0) as u16;
                (quality > 0 && !tag.is_empty()).then_some((quality, index, tag))
            })
            .collect();
        ranges.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        for (_, _, tag) in ranges {
            let primary = tag.split('-').next().unwrap_or_default();
            if primary.eq_ignore_ascii_case("zh") {
                return Self::Zh;
            }
            if primary.eq_ignore_ascii_case("en") {
                return Self::En;
            }
        }
        Self::En
    }

    /// The `lang` attribute of the page.
    pub fn tag(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Zh => "zh-CN",
        }
    }

    /// The page strings.
    pub fn t(self) -> &'static Text {
        match self {
            Self::En => &EN,
            Self::Zh => &ZH,
        }
    }
}

/// Fills the `{}` placeholders of `template` with `values`, in order.
pub fn fill(template: &str, values: &[&str]) -> String {
    let mut out = String::with_capacity(template.len() + 16);
    let mut values = values.iter();
    let mut rest = template;
    while let Some(index) = rest.find("{}") {
        out.push_str(&rest[..index]);
        out.push_str(values.next().copied().unwrap_or_default());
        rest = &rest[index + 2..];
    }
    out.push_str(rest);
    out
}

macro_rules! texts {
    ($($key:ident: $en:expr, $zh:expr;)*) => {
        /// Every string of the translated pages, in one language.
        #[derive(Debug)]
        pub struct Text {
            $(#[allow(missing_docs)] pub $key: &'static str,)*
        }
        /// English.
        pub static EN: Text = Text { $($key: $en,)* };
        /// Chinese (simplified).
        pub static ZH: Text = Text { $($key: $zh,)* };
        /// Every string, for the test that checks placeholders.
        #[cfg(test)]
        fn all() -> Vec<(&'static str, &'static str, &'static str)> {
            vec![$((stringify!($key), EN.$key, ZH.$key),)*]
        }
    };
}

texts! {
    // Frame
    skip: "Skip to content", "跳到正文";
    menu: "Menu", "菜单";
    files: "Files", "文件";
    favorites: "Favorites", "收藏";
    admin: "Admin", "管理";
    account: "Account", "账号";
    sign_in: "Sign in", "登录";
    sign_out: "Sign out", "退出登录";
    search: "Search", "搜索";
    search_files: "Search files", "搜索文件";
    theme_system: "Theme: system", "主题：跟随系统";
    theme_light: "Theme: light", "主题：浅色";
    theme_dark: "Theme: dark", "主题：深色";
    theme_title: "Switch between light, dark and system theme", "在浅色、深色和跟随系统之间切换";

    // Sign-in
    sign_in_lead: "Use your web login password. App passwords of devices do not work here.", "请使用网页登录密码。设备的 app password 不能在这里登录。";
    username: "Username", "用户名";
    password: "Password", "密码";
    wrong_password: "Wrong username or password.", "用户名或密码错误。";
    form_expired_sign_in: "The form has expired. Please sign in again.", "表单已过期，请重新登录。";
    session_ended: "Your session has ended. Please sign in again.", "会话已结束，请重新登录。";
    signed_out: "You are signed out.", "已退出登录。";

    // Messages
    request_blocked: "Request blocked", "请求被拦截";
    from_other_site: "This form was sent from another site.", "这个表单来自其他网站。";
    form_expired: "The form has expired. Go back, reload the page and try again.", "表单已过期。请返回、刷新页面后重试。";
    too_many_attempts: "Too many attempts", "尝试次数过多";
    too_many_attempts_lead: "There were too many failed sign-ins from your network. Try again in {} seconds.", "你的网络登录失败次数过多，请 {} 秒后再试。";
    unavailable: "Temporarily unavailable", "暂时不可用";
    unavailable_lead: "The server cannot check your password right now. Try again in a moment.", "服务器暂时无法验证密码，请稍后再试。";
    error: "Something went wrong", "出错了";
    error_lead: "The server could not complete the request. The details are in the server log.", "服务器未能完成请求，详情见服务器日志。";
    bad_request: "Bad request", "请求无效";
    not_found: "Not found", "未找到";
    not_found_lead: "There is nothing at this address, or you have no access to it.", "这个地址没有内容，或者你没有权限访问。";
    back_to_files: "Back to files", "返回文件";

    // Login Flow v2
    connect_device: "Connect a device", "连接设备";
    flow_sign_in_lead: "wants to access your account. Sign in to continue; you will be asked to confirm.", "想要访问你的账号。请先登录，之后还需要你确认。";
    flow_sign_in_note: "Use your web login password. App passwords of other devices do not work here.", "请使用网页登录密码。其他设备的 app password 不能在这里登录。";
    log_in: "Log in", "登录";
    grant_title: "Grant access", "授权访问";
    grant_question: "Grant access?", "授权访问？";
    grant_asks: "asks for access to your account", "请求访问你的账号";
    grant_note: "If you grant access, this device gets its own app password with access to all your files. You can revoke it at any time. Only continue if you just started this sign-in in the app.", "授权后，这台设备会得到一个独立的 app password，可以访问你的全部文件，你可以随时吊销。只有在你刚刚从 app 里发起登录时才继续。";
    grant: "Grant access", "授权";
    cancel: "Cancel", "取消";
    not_you: "Not {}?", "不是 {}？";
    log_out: "Log out", "退出";
    link_expired: "Link expired", "链接已过期";
    link_expired_heading: "This link has expired", "这个链接已过期";
    link_expired_lead: "The sign-in request was already used, cancelled or is too old. Start the sign-in again in your app.", "这个登录请求已被使用、已取消或已过期。请在 app 里重新开始登录。";
    access_granted: "Access granted", "已授权";
    access_granted_lead: "is now connected to your account.", "已连接到你的账号。";
    close_and_return: "You can close this window and return to the app.", "可以关闭这个窗口，回到 app。";
    access_denied: "Access denied", "已拒绝";
    access_denied_lead: "did not get access to your account.", "没有获得访问你账号的权限。";
    close_window: "You can close this window.", "可以关闭这个窗口。";
    unknown_action: "Unknown action.", "未知操作。";

    // Files: listing
    all_files: "All files", "全部文件";
    name: "Name", "名称";
    size: "Size", "大小";
    modified: "Modified", "修改时间";
    sort_by: "Sort by", "排序";
    upload: "Upload", "上传";
    upload_files: "Upload files", "上传文件";
    upload_folder: "Upload folder", "上传文件夹";
    new_folder: "New folder", "新建文件夹";
    folder_name: "Folder name", "文件夹名称";
    create: "Create", "创建";
    download: "Download", "下载";
    download_folder: "Download folder", "下载文件夹";
    download_zip: "Download as .zip", "打包下载 .zip";
    rename: "Rename", "重命名";
    move_to: "Move", "移动";
    delete: "Delete", "删除";
    more_actions: "More actions", "更多操作";
    add_favorite: "Add to favorites", "加入收藏";
    remove_favorite: "Remove from favorites", "取消收藏";
    favorite: "Favorite", "已收藏";
    select: "Select", "选择";
    select_all: "Select all", "全选";
    selected: "{} selected", "已选 {} 项";
    selection: "Selection", "所选项";
    items: "{} items", "{} 项";
    one_item: "1 item", "1 项";
    folder: "Folder", "文件夹";
    empty_folder: "This folder is empty.", "这个文件夹是空的。";
    empty_folder_hint: "Upload files or create a folder to get started.", "上传文件或新建文件夹。";
    previous: "Previous", "上一页";
    next: "Next", "下一页";
    page_of: "Page {} of {}", "第 {} / {} 页";
    storage: "Storage", "存储";
    used: "{} used", "已用 {}";
    free_on_server: "{} free on the server", "服务器剩余 {}";
    places: "Places", "位置";
    choose_files: "Choose files", "选择文件";
    replace_existing: "Replace files with the same name", "替换同名文件";
    drop_hint: "You can also drop files and folders anywhere on this page.", "也可以把文件和文件夹拖到页面任意位置。";
    drop_here: "Drop files to upload them to {}", "松开即可上传到 {}";
    today: "Today", "今天";
    yesterday: "Yesterday", "昨天";

    // Files: notices
    notice_created: "Created the folder {}.", "已创建文件夹 {}。";
    notice_uploaded: "Uploaded {} files.", "已上传 {} 个文件。";
    notice_uploaded_one: "Uploaded 1 file.", "已上传 1 个文件。";
    notice_skipped: "Skipped {} files that already exist.", "跳过了 {} 个已存在的文件。";
    notice_renamed: "Renamed to {}.", "已重命名为 {}。";
    notice_moved: "Moved {} items.", "已移动 {} 项。";
    notice_moved_one: "Moved 1 item.", "已移动 1 项。";
    notice_deleted: "Deleted {} items.", "已删除 {} 项。";
    notice_deleted_one: "Deleted 1 item.", "已删除 1 项。";
    notice_favorited: "Added to favorites.", "已加入收藏。";
    notice_unfavorited: "Removed from favorites.", "已取消收藏。";
    notice_nothing_selected: "Nothing was selected.", "没有选中任何项。";
    err_exists: "Something with this name already exists here.", "这里已经有同名的文件或文件夹。";
    err_name: "This name cannot be used. Names must not be empty, \".\" or \"..\", or contain \"/\".", "不能使用这个名称：名称不能为空、不能是 \".\" 或 \"..\"，也不能包含 \"/\"。";
    err_not_found: "It no longer exists. Someone may have moved or deleted it.", "它已不存在，可能已被移动或删除。";
    err_forbidden: "You cannot change this location.", "你不能修改这个位置。";
    err_locked: "It is locked by another app. Try again when the app has closed it.", "它正被其他应用锁定，请等该应用关闭后再试。";
    err_storage: "There is not enough free space on the server.", "服务器剩余空间不足。";
    err_into_itself: "A folder cannot be moved into itself.", "文件夹不能移动到它自己里面。";
    err_failed: "The server could not complete this. The details are in the server log.", "服务器未能完成操作，详情见服务器日志。";
    err_busy: "Too many downloads are running. Try again in a moment.", "正在进行的打包下载太多，请稍后再试。";
    err_too_big: "This folder has too many entries to download as one .zip.", "这个文件夹包含的条目太多，无法打包为一个 .zip 下载。";
    err_partial: "{} of {} items could not be changed.", "{} / {} 项未能完成。";

    // Files: action pages
    rename_title: "Rename {}", "重命名 {}";
    new_name: "New name", "新名称";
    move_title: "Move {}", "移动 {}";
    move_items_title: "Move {} items", "移动 {} 项";
    move_lead: "Choose the folder to move to.", "选择要移动到的文件夹。";
    move_here: "Move here", "移动到这里";
    up: "Up", "上一级";
    no_subfolders: "No folders here.", "这里没有文件夹。";
    current_folder: "Current folder: {}", "当前文件夹：{}";
    delete_title: "Delete {}?", "删除 {}？";
    delete_items_title: "Delete {} items?", "删除 {} 项？";
    delete_lead: "Deleted files and folders cannot be restored: there is no trash.", "删除后无法恢复：没有回收站。";
    delete_folder_note: "Everything inside the folder is deleted too.", "文件夹里的全部内容也会被删除。";

    // Files: file page and previews
    file_details: "Details", "详情";
    kind: "Type", "类型";
    no_preview: "There is no preview for this kind of file.", "这种文件没有预览。";
    preview_truncated: "Only the first part of the file is shown.", "只显示了文件的开头部分。";
    preview_blocked: "Web pages, SVG and PDF files are not opened in the browser, to keep your account safe. Download them instead.", "为保护账号安全，网页、SVG 和 PDF 文件不会在浏览器里打开，请下载后查看。";

    // Search and favorites
    search_title: "Search", "搜索";
    search_results: "Results for “{}”", "“{}”的搜索结果";
    search_in: "in {}", "范围：{}";
    no_results: "No files or folders match.", "没有匹配的文件或文件夹。";
    search_limited: "Showing the first {} results. Refine the search to see others.", "只显示前 {} 个结果，请缩小搜索范围。";
    search_too_short: "Enter at least 2 characters.", "请至少输入 2 个字符。";
    no_favorites: "No favorites yet.", "还没有收藏。";
    no_favorites_hint: "Use “Add to favorites” on a file or folder. Favorites are shared with the desktop and mobile apps.", "在文件或文件夹的菜单里选择“加入收藏”。收藏会同步到桌面端和手机 app。";

    // Uploads (script)
    js_uploads: "Uploads", "上传";
    js_waiting: "Waiting", "等待中";
    js_uploading: "{} of {}", "{} / {}";
    js_finishing: "Finishing…", "正在完成…";
    js_done: "Done", "完成";
    js_replaced: "Replaced", "已替换";
    js_skipped: "Already exists, skipped", "已存在，已跳过";
    js_failed: "Failed", "失败";
    js_retrying: "Connection lost, retrying…", "连接中断，正在重试…";
    js_cancelled: "Cancelled", "已取消";
    js_retry: "Retry", "重试";
    js_cancel_all: "Cancel all", "全部取消";
    js_close: "Close", "关闭";
    js_conflict: "{} already exists. Replace it?", "{} 已存在，要替换吗？";
    js_leave: "Uploads are still running. Leave the page?", "还有文件正在上传，确定离开页面吗？";
    js_left: "{} left", "剩余 {}";

    // Account
    account_title: "Account", "账号";
    profile: "Profile", "个人信息";
    display_name: "Display name", "显示名称";
    display_name_note: "The name the apps show for your account.", "app 里显示的名称。";
    save: "Save", "保存";
    web_password: "Web login password", "网页登录密码";
    web_password_note: "Used to sign in here and to connect devices. Changing it signs you out in every other browser.", "用于在这里登录和连接设备。修改后其他浏览器都会退出登录。";
    current_password: "Current password", "当前密码";
    new_password: "New password", "新密码";
    repeat_password: "Repeat new password", "再次输入新密码";
    change_password: "Change password", "修改密码";
    devices: "Devices and app passwords", "设备和 app password";
    devices_note: "One per device. Revoking one signs that device out at once.", "每台设备一个。吊销后该设备会立即退出。";
    no_devices: "No devices yet. Apps get an app password when you connect them, or create one below.", "还没有设备。连接 app 时会自动创建，也可以在下面手动创建。";
    label: "Label", "名称";
    access: "Access", "权限";
    last_used: "Last used", "最近使用";
    never_used: "Never used", "从未使用";
    created: "Created {}", "创建于 {}";
    expires: "Expires {}", "{} 过期";
    no_expiry: "Does not expire", "永不过期";
    revoke: "Revoke", "吊销";
    new_app_password: "New app password", "新建 app password";
    new_app_password_note: "For WebDAV clients such as Finder, Windows Explorer or rclone. Shown once after it is created.", "用于 Finder、Windows 资源管理器、rclone 等 WebDAV 客户端。创建后只显示一次。";
    expires_after: "Expires after (days)", "有效期（天）";
    never: "Never", "永久";
    access_full: "All files, read and write", "全部文件，可读写";
    access_full_note: "Mounts / with full access.", "以完全权限挂载 /。";
    access_view: "All files, read only", "全部文件，只读";
    access_view_note: "Mounts / with view access.", "以只读权限挂载 /。";
    access_custom: "Selected folders", "指定文件夹";
    access_custom_note: "Up to three mounts; empty rows are ignored.", "最多三个挂载，空行会被忽略。";
    mount_as: "Shown to the device as", "在设备上显示为";
    mount_folder: "Folder in your files", "你的文件中的文件夹";
    create_app_password: "Create app password", "创建 app password";
    app_password_created: "App password created", "app password 已创建";
    app_password_created_lead: "Enter it on the device now. It is not stored in readable form and will not be shown again.", "请现在把它填到设备上。它不会以可读形式保存，也不会再次显示。";
    server: "Server", "服务器";
    webdav_address: "WebDAV address", "WebDAV 地址";
    done: "Done", "完成";
    notice_display_name: "Your display name was changed.", "显示名称已修改。";
    notice_revoked: "The app password was revoked.", "app password 已吊销。";
    notice_password_changed: "Your password was changed. Other browsers were signed out.", "密码已修改，其他浏览器已退出登录。";
    err_current_password: "The current password is wrong.", "当前密码不正确。";
    err_passwords_differ: "The new passwords do not match.", "两次输入的新密码不一致。";
    err_password_short: "The new password must have at least 8 characters.", "新密码至少需要 8 个字符。";
    err_display_name: "The display name must not be empty or longer than 255 characters.", "显示名称不能为空，也不能超过 255 个字符。";
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn lang(value: &'static str) -> Lang {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static(value));
        Lang::from_headers(&headers)
    }

    #[test]
    fn the_preferred_supported_language_wins() {
        assert_eq!(Lang::from_headers(&HeaderMap::new()), Lang::En);
        assert_eq!(lang("zh-CN,zh;q=0.9,en;q=0.8"), Lang::Zh);
        assert_eq!(lang("en-US,en;q=0.9,zh-CN;q=0.8"), Lang::En);
        assert_eq!(
            lang("de-DE,de;q=0.9,zh-TW;q=0.5"),
            Lang::Zh,
            "first supported one"
        );
        assert_eq!(lang("en;q=0.4, zh-Hans;q=0.6"), Lang::Zh, "by quality");
        assert_eq!(lang("zh;q=0, en"), Lang::En, "q=0 means not acceptable");
        assert_eq!(lang("fr"), Lang::En);
        assert_eq!(lang("*"), Lang::En);
    }

    #[test]
    fn placeholders_are_filled_in_order() {
        assert_eq!(fill("Page {} of {}", &["2", "5"]), "Page 2 of 5");
        assert_eq!(fill("{} items", &[]), " items");
        assert_eq!(fill("none", &["x"]), "none");
    }

    #[test]
    fn translations_keep_the_placeholders() {
        for (key, en, zh) in all() {
            assert_eq!(
                en.matches("{}").count(),
                zh.matches("{}").count(),
                "{key}: {en:?} / {zh:?}"
            );
            assert!(!en.is_empty() && !zh.is_empty(), "{key}");
        }
    }
}
