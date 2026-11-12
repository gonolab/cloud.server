//! The languages of the HTML pages: English and Chinese (simplified).
//!
//! The language of a page follows the browser's `Accept-Language` ([`Lang::from_headers`]).
//! Every string a page shows is a field of [`Text`]; `texts!` defines each one in both
//! languages on one line, so a translation can never be missing. Strings with values use
//! `{}` placeholders, filled in order by [`fill`]; counts pick their singular or plural form
//! with [`count`].

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

/// `one` for a count of 1, else `many` with the count as its first value.
pub fn count(one: &str, many: &str, n: impl std::fmt::Display, rest: &[&str]) -> String {
    let n = n.to_string();
    if n == "1" {
        fill(one, rest)
    } else {
        let mut values = vec![n.as_str()];
        values.extend_from_slice(rest);
        fill(many, &values)
    }
}

/// `3 days 4 hours`, `5 hours 2 minutes`, `12 minutes` in the page's language.
pub fn duration(t: &Text, seconds: i64) -> String {
    let seconds = seconds.max(0);
    let (days, hours, minutes) = (
        seconds / 86_400,
        seconds % 86_400 / 3600,
        seconds % 3600 / 60,
    );
    let days_text = count(t.one_day, t.n_days, days, &[]);
    let hours_text = count(t.one_hour, t.n_hours, hours, &[]);
    let minutes_text = count(t.one_minute, t.n_minutes, minutes, &[]);
    if days > 0 {
        format!("{days_text} {hours_text}")
    } else if hours > 0 {
        format!("{hours_text} {minutes_text}")
    } else {
        minutes_text
    }
}

/// `just now`, `5 min ago`, `3 h ago`, `2 days ago` (up to a month), else the date.
pub fn ago(t: &Text, now: i64, then: i64, date: impl FnOnce(i64) -> String) -> String {
    let seconds = (now - then).max(0);
    match seconds {
        0..60 => t.just_now.to_owned(),
        60..3600 => fill(t.minutes_ago, &[&(seconds / 60).to_string()]),
        3600..86_400 => fill(t.hours_ago, &[&(seconds / 3600).to_string()]),
        86_400..2_592_000 => count(t.day_ago, t.days_ago, seconds / 86_400, &[]),
        _ => date(then),
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
    err_display_name: "The display name must not be empty, longer than 255 characters or contain control characters.", "显示名称不能为空、不能超过 255 个字符，也不能包含控制字符。";
    err_password_policy: "The password must be at most 1024 bytes long and must not contain control characters.", "密码不能超过 1024 字节，也不能包含控制字符。";
    err_username: "Usernames use lowercase letters, digits, \".\", \"_\", \"-\" and \"@\", at most 64 characters.", "用户名只能使用小写字母、数字、\".\"、\"_\"、\"-\" 和 \"@\"，最多 64 个字符。";
    err_user_exists: "A user named {} already exists.", "已经有名为 {} 的用户。";
    err_last_admin: "{} is the last enabled admin. Make another account an admin first.", "{} 是最后一个启用的管理员，请先把其他账号设为管理员。";
    err_label_invalid: "The label must not be empty, longer than 100 characters or contain control characters.", "名称不能为空、不能超过 100 个字符，也不能包含控制字符。";
    err_expiry: "The expiry must be a number of days between 1 and 3650.", "有效期必须是 1 到 3650 之间的天数。";
    err_mount_paths: "Every mount needs both paths.", "每个挂载都需要填写两个路径。";
    err_no_mounts: "Enter at least one folder for “Selected folders”.", "选择“指定文件夹”时至少要填写一个文件夹。";
    err_invalid_path: "Invalid path {}.", "路径 {} 无效。";
    err_scopes: "The mounts do not fit together: {}.", "挂载之间有冲突：{}。";

    // Time words of the admin UI
    just_now: "just now", "刚刚";
    minutes_ago: "{} min ago", "{} 分钟前";
    hours_ago: "{} h ago", "{} 小时前";
    day_ago: "1 day ago", "1 天前";
    days_ago: "{} days ago", "{} 天前";
    one_day: "1 day", "1 天";
    n_days: "{} days", "{} 天";
    one_hour: "1 hour", "1 小时";
    n_hours: "{} hours", "{} 小时";
    one_minute: "1 minute", "1 分钟";
    n_minutes: "{} minutes", "{} 分钟";
    expired: "Expired {}", "已于 {} 过期";

    // Admin UI: frame
    a_overview: "Overview", "概览";
    a_users: "Users", "用户";
    a_footer_protocol: "Nextcloud protocol", "Nextcloud 协议";
    a_footer_instance: "instance", "实例";
    a_source: "Source", "源代码";
    a_sign_in_title: "Sign in to the admin UI", "登录管理界面";
    a_not_admin: "Not an administrator", "不是管理员";
    a_not_admin_before: "You are signed in as ", "你当前登录的账号是 ";
    a_not_admin_after: ", which is not an admin account. Sign out and sign in with an admin account to continue.", "，它不是管理员账号。请退出后用管理员账号登录。";
    a_not_admin_error: "This account is not an administrator.", "这个账号不是管理员。";

    // Admin UI: overview
    a_running: "Running", "运行中";
    a_up: "up {}", "已运行 {}";
    a_manage_users: "Manage users", "管理用户";
    a_check_config: "Check the configuration:", "请检查配置：";
    a_case_warning: "the data directory is on a case-insensitive file system, so names that differ only in case (Report.pdf, report.pdf) cannot coexist. A case-sensitive file system (Linux with ext4, XFS or Btrfs) is recommended.", "数据目录所在的文件系统不区分大小写，只有大小写不同的名称（Report.pdf、report.pdf）不能同时存在。建议使用区分大小写的文件系统（Linux 上的 ext4、XFS 或 Btrfs）。";
    a_app_passwords: "App passwords", "App password";
    a_used_today: "{} used in the last 24 h", "最近 24 小时用过 {} 个";
    a_storage_used: "Storage used", "已用存储";
    a_live_push: "Live push connections", "实时推送连接";
    a_user_connected: "1 user connected", "1 个用户在线";
    a_users_connected: "{} users connected", "{} 个用户在线";
    a_push_off: "notify_push is off", "notify_push 已关闭";
    a_admins_disabled_one: "1 admin · {} disabled", "1 个管理员 · {} 个已停用";
    a_admins_disabled: "{} admins · {} disabled", "{} 个管理员 · {} 个已停用";
    a_server: "Server", "服务器";
    a_server_note: "From the configuration file and the running process. Change settings in the file and restart.", "来自配置文件和正在运行的进程。修改设置请编辑配置文件后重启。";
    a_connect: "Connect a client", "连接客户端";
    a_connect_note: "Nextcloud apps only need the server address; they sign in through the browser (Login Flow v2).", "Nextcloud app 只需要服务器地址，会通过浏览器登录（Login Flow v2）。";
    a_server_address: "Server address", "服务器地址";
    a_webdav_clients: "WebDAV (Finder, Explorer, rclone)", "WebDAV（Finder、资源管理器、rclone）";
    a_websocket: "notify_push WebSocket", "notify_push WebSocket";
    a_data_dir: "Data directory", "数据目录";
    a_file_system: "File system", "文件系统";
    a_case_insensitive: "case-insensitive", "不区分大小写";
    a_case_sensitive: "case-sensitive", "区分大小写";
    a_unknown: "unknown", "未知";
    a_used_by_files: "Used by files", "文件占用";
    a_free: "Free", "可用";
    a_free_of: "{} of {}", "{} / 共 {}";
    a_free_note: "{} free of {}", "可用 {} / 共 {}";
    a_free_unknown: "Free space unknown", "可用空间未知";
    a_uploads: "Uploads in progress", "进行中的上传";
    a_database: "Database", "数据库";
    a_database_size: "Database size", "数据库大小";
    a_features: "Features", "功能";
    a_on: "On", "开启";
    a_off: "Off", "关闭";
    a_about: "About", "关于";
    a_about_text: "Self-hosted WebDAV file server compatible with Nextcloud clients, built on dav-server-rs.", "自托管的 WebDAV 文件服务器，兼容 Nextcloud 客户端，基于 dav-server-rs。";
    a_license: "License", "许可证";
    a_guides: "Guides", "指南";
    a_reverse_proxy: "Reverse proxy", "反向代理";
    a_fact_version: "Version", "版本";
    a_fact_protocol: "Nextcloud protocol", "Nextcloud 协议";
    a_fact_instance: "Instance id", "实例 id";
    a_fact_started: "Started", "启动时间";
    a_fact_public_url: "Public URL", "公开地址";
    a_fact_listening: "Listening on", "监听地址";
    a_fact_proxies: "Trusted proxies", "受信任的代理";
    a_fact_config: "Configuration", "配置文件";
    a_fact_log: "Log", "日志";
    a_none: "none", "无";
    a_push_detail: "Ping {} s · debounce {} s · {} per user", "心跳 {} 秒 · 合并 {} 秒 · 每用户 {} 个";
    a_push_off_detail: "Clients poll for changes", "客户端轮询变更";
    a_flow_waiting_one: "1 sign-in waiting", "1 个登录等待中";
    a_flows_waiting: "{} sign-ins waiting", "{} 个登录等待中";
    a_chunked: "Chunked upload v2", "分块上传 v2";
    a_chunked_detail: "Unfinished uploads expire after {} h", "未完成的上传 {} 小时后过期";
    a_locks: "WebDAV locks", "WebDAV 锁";
    a_locks_detail: "At most {} · {} held now", "最长 {} · 当前 {} 个";
    a_web_admin: "Web admin", "网页管理";
    a_web_files: "Web file UI", "网页文件界面";
    a_web_files_detail: "At /apps/files/", "位于 /apps/files/";
    a_web_files_off: "Turned off in [files_ui]", "已在 [files_ui] 中关闭";
    a_session_one: "1 browser session", "1 个浏览器会话";
    a_sessions: "{} browser sessions", "{} 个浏览器会话";

    // Admin UI: users
    a_accounts_summary_one: "1 account · {} · {} disabled", "1 个账号 · {} · {} 个已停用";
    a_accounts_summary: "{} accounts · {} · {} disabled", "{} 个账号 · {} · {} 个已停用";
    a_admin_one: "1 admin", "1 个管理员";
    a_admins: "{} admins", "{} 个管理员";
    a_new_user: "New user", "新建用户";
    a_user: "User", "用户";
    a_role: "Role", "角色";
    a_status: "Status", "状态";
    a_storage: "Storage", "存储";
    a_created: "Created", "创建时间";
    a_admin_badge: "Admin", "管理员";
    a_user_badge: "User", "用户";
    a_enabled: "Enabled", "已启用";
    a_disabled: "Disabled", "已停用";
    a_manage: "Manage", "管理";
    a_deleted_notice: "The user was deleted. Their files were moved to deleted/.", "用户已删除，其文件已移到 deleted/。";
    a_new_user_sub: "The user signs in to the web pages and Login Flow with this password; devices get their own app passwords.", "用户用这个密码登录网页和 Login Flow；设备会得到各自的 app password。";
    a_username_hint: "Lowercase letters, digits, “.”, “_”, “-” and “@”. Part of every WebDAV URL.", "小写字母、数字、“.”、“_”、“-” 和 “@”。会出现在所有 WebDAV 地址中。";
    a_optional: "Optional.", "可选。";
    a_repeat_password: "Repeat password", "再次输入密码";
    a_administrator: "Administrator", "管理员";
    a_administrator_note: "Can open this admin UI and manage every account.", "可以打开管理界面并管理所有账号。";
    a_create_user: "Create user", "创建用户";

    // Admin UI: one user
    a_this_is_you: "This is your account.", "这是你自己的账号。";
    a_remove_admin: "Remove admin", "取消管理员";
    a_make_admin: "Make admin", "设为管理员";
    a_disable: "Disable account", "停用账号";
    a_enable: "Enable account", "启用账号";
    a_devices_note: "One per device. Revoking signs that device out at once.", "每台设备一个。吊销后该设备会立即退出。";
    a_no_app_passwords: "No app passwords yet. Devices get one through Login Flow, or create one below.", "还没有 app password。设备会通过 Login Flow 获得，也可以在下面创建。";
    a_shown_once: "Shown once after it is created.", "创建后只显示一次。";
    a_label_example: "Work laptop", "工作笔记本";
    a_mount_folder: "Folder in the user's files", "用户文件中的文件夹";
    a_account: "Account", "账号";
    a_user_id: "User id", "用户 id";
    a_changed: "Changed", "修改时间";
    a_display_name_note: "The name clients show for this account.", "客户端为这个账号显示的名称。";
    a_change_display_name: "Change display name", "修改显示名称";
    a_password_note: "Used for the web pages, Login Flow and this admin UI. Setting it signs the user out of open browser sessions.", "用于网页、Login Flow 和管理界面。设置后该用户已打开的浏览器会话都会退出。";
    a_repeat: "Repeat", "再次输入";
    a_set_password: "Set password", "设置密码";
    a_delete_user: "Delete user", "删除用户";
    a_delete_user_note: "Removes the account, its app passwords and metadata. Files are moved to deleted/, not erased.", "删除账号、它的 app password 和元数据。文件会移到 deleted/，不会被擦除。";
    a_cannot_delete_self: "You cannot delete the account you are signed in with.", "不能删除你当前登录的账号。";
    a_cannot_disable_self: "You cannot disable the account you are signed in with.", "不能停用你当前登录的账号。";
    a_cannot_demote_self: "You cannot demote the account you are signed in with.", "不能取消你当前登录账号的管理员身份。";
    a_delete_named: "Delete {}…", "删除 {}…";
    a_passwords_differ: "The passwords do not match.", "两次输入的密码不一致。";
    a_notice_created: "User {} was created.", "用户 {} 已创建。";
    a_notice_enabled: "The account was enabled.", "账号已启用。";
    a_notice_disabled: "The account was disabled. Its devices and browser sessions are signed out.", "账号已停用，其设备和浏览器会话已退出。";
    a_notice_promoted: "{} is now an admin and can sign in to this admin UI.", "{} 现在是管理员，可以登录管理界面。";
    a_notice_demoted: "{} is no longer an admin. Their files and devices are not affected.", "{} 已不再是管理员，其文件和设备不受影响。";
    a_notice_renamed: "The display name was changed.", "显示名称已修改。";
    a_notice_password: "The web login password was set.", "网页登录密码已设置。";
    a_no_such_user: "No such user", "没有这个用户";
    a_no_such_user_lead: "There is no account named {}.", "没有名为 {} 的账号。";
    a_all_users: "All users", "全部用户";

    // Admin UI: delete and created
    a_delete_question: "Delete {}?", "删除 {}？";
    a_delete_undone: "This cannot be undone from the admin UI.", "在管理界面中无法撤销。";
    a_delete_effect_one: "The account, its app password and its browser sessions are removed; its devices are signed out.", "账号、它的 1 个 app password 和浏览器会话都会被删除，设备会退出登录。";
    a_delete_effect: "The account, its {} app passwords and its browser sessions are removed; its devices are signed out.", "账号、它的 {} 个 app password 和浏览器会话都会被删除，设备会退出登录。";
    a_delete_files: "Its files are moved to deleted/ in the data directory; nothing is erased.", "它的文件会移到数据目录的 deleted/ 中，不会被擦除。";
    a_new_app_password_crumb: "New app password", "新建 app password";
    a_nothing_to_show: "Nothing to show", "没有可显示的内容";
    a_nothing_to_show_lead: "A new app password is shown only once, right after it was created. Create another one if it was not written down.", "新的 app password 只在创建后显示一次。如果没有记下，请再创建一个。";
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
