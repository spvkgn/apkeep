use super::*;

#[test]
fn completed_and_zero_length_callbacks_are_reusable_without_leaking_owners() {
    let progress = Rc::new(MultiProgress::with_draw_target(
        indicatif::ProgressDrawTarget::hidden(),
    ));
    {
        let make_callback = progress_wrapper(Rc::clone(&progress));
        let zero = make_callback("empty.apk".to_owned(), 0);
        zero(0);
        zero(0);
        let normal = make_callback("complete.apk".to_owned(), 10);
        normal(4);
        normal(10);
        normal(10);
    }
    assert_eq!(Rc::strong_count(&progress), 1);
}
