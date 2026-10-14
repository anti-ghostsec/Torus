//! The pure part of the builder: a site is data, and rendering it yields
//! HTML and CSS with no scripts and no third-party requests.
//!
//! Nothing here touches the disk or the network, so the same code can run
//! in the editor, in the sandboxed host, and in tests.

mod compile;
mod lint;
mod model;
pub mod starters;

pub use compile::{
    check, render_canvas, APPROVE_PATH, render_page, render_progress, stylesheet, Canvas, Data, NoData, Viewer, Visit, FILE_PATH, FORM_PATH,
    NEXT_FIELD, PAGE_PARAM, PROGRESS_PATH, SIZE_PARAM, WAITED_PARAM, REMOVE_PATH, SEARCH_MAX, SEARCH_PARAM, UPLOAD_PARAM,
    PARENT_FIELD, PASSWORD_FIELD, PASSWORD_MAX, PASSWORD_MIN, SIGN_IN_PATH, SIGN_OUT_PATH, SIGN_UP_PATH, STYLE_PATH,
    TOKEN_FIELD,
};
pub use lint::{lint, Finding, Severity};
pub use model::{
    Align, Audience, Block, Collection, Field, FieldKind, Layout, Limits, Page, Record, Scope, Site, Theme, HOME_SLUG,
    ID_TOKEN, SEALED_FIELD, USERS, USER_NAME,
};
