mod apk_validation;
pub const MAX_PARALLEL: usize = 16;
pub fn valid_parallel(parallel: usize) -> bool {
    (1..=MAX_PARALLEL).contains(&parallel)
}
pub(super) fn check_parallel(apps: &[(String, Option<String>)], parallel: usize) -> bool {
    if valid_parallel(parallel) {
        return true;
    }
    crate::results::batch_error(apps, crate::results::Reason::InvalidInput);
    eprintln!("parallel must be between 1 and 16");
    false
}
pub mod apkpure;
pub mod fdroid;
pub mod google_play;
pub mod huawei_app_gallery;
pub mod rustore;
