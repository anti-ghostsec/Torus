use std::collections::BTreeSet;

use serde::Serialize;

use crate::model::{
    valid_slug, Block, Collection, FieldKind, Scope as ListScope, Site, HOME_SLUG, ID_TOKEN, USERS, USER_NAME,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Blocks publishing.
    Error,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub severity: Severity,
    /// Slug of the page the finding is on, empty for site-wide findings.
    pub page: String,
    pub message: String,
}

/// Where a link points, as far as leak prevention cares.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LinkTarget {
    /// A path on this site.
    Internal,
    Onion,
    Clearnet,
    /// Not http(s) and not a local path: `javascript:`, `data:`, `mailto:`...
    Forbidden,
}

pub(crate) fn classify_link(href: &str) -> LinkTarget {
    let href = href.trim();
    if href.starts_with('/') && !href.starts_with("//") {
        return LinkTarget::Internal;
    }
    let lower = href.to_ascii_lowercase();
    let Some(rest) = lower.strip_prefix("http://").or_else(|| lower.strip_prefix("https://")) else {
        return LinkTarget::Forbidden;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Userinfo can disguise the real host, so refuse it outright.
    if authority.is_empty() || authority.contains('@') {
        return LinkTarget::Forbidden;
    }
    let host = authority.rsplit_once(':').map_or(authority, |(host, _port)| host);
    if host.ends_with(".onion") {
        LinkTarget::Onion
    } else {
        LinkTarget::Clearnet
    }
}

/// What a block can refer to from where it stands.
struct Scope<'a> {
    site: &'a Site,
    /// The collection whose record is being shown: the enclosing list's, or
    /// the template page's.
    record: Option<&'a Collection>,
}

/// Checks a site for anything that would break it or identify its author.
pub fn lint(site: &Site) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut site_wide = |severity, message: String| {
        out.push(Finding { severity, page: String::new(), message });
    };

    if !site.pages.iter().any(|p| p.slug == HOME_SLUG) {
        site_wide(Severity::Error, "The site needs a home page with the slug \"index\".".into());
    }
    if contains_email(&site.title) {
        site_wide(Severity::Warning, "The site title contains an email address.".into());
    }

    if site.accounts {
        match site.collection(USERS).map(|users| (users, users.field(USER_NAME))) {
            None => site_wide(Severity::Error, format!("Accounts need a collection called \"{USERS}\".")),
            Some((_, None)) => {
                site_wide(Severity::Error, format!("The \"{USERS}\" collection needs a field called \"{USER_NAME}\"."));
            }
            Some((users, Some(name))) => {
                if name.kind != FieldKind::Text || !name.required {
                    site_wide(Severity::Error, format!("The \"{USER_NAME}\" field of \"{USERS}\" must be required, one-line text."));
                }
                if users.parent.is_some() || users.members_only {
                    site_wide(Severity::Error, format!("The \"{USERS}\" collection cannot belong to another or be members-only."));
                }
            }
        }
    } else {
        if site.collection(USERS).is_some() {
            site_wide(Severity::Error, format!("The collection name \"{USERS}\" is reserved for accounts. Turn accounts on or rename it."));
        }
        let needs_accounts = |b: &Block| {
            matches!(
                b,
                Block::SignUp { .. }
                    | Block::SignIn { .. }
                    | Block::SignOut { .. }
                    | Block::Gate { .. }
                    | Block::Author { .. }
                    | Block::Remove { .. }
                    | Block::Approve { .. }
            )
        };
        if site.any_block(&needs_accounts) || site.collections.iter().any(|c| c.members_only) {
            site_wide(Severity::Error, "Part of this site needs accounts, which are turned off.".into());
        }
    }

    let mut names = BTreeSet::new();
    for collection in &site.collections {
        let name = &collection.name;
        if !valid_slug(name) {
            site_wide(
                Severity::Error,
                format!("The collection name \"{name}\" may only use lowercase letters, digits and dashes."),
            );
        } else if !names.insert(name.as_str()) {
            site_wide(Severity::Error, format!("More than one collection is called \"{name}\"."));
        }
        if collection.fields.is_empty() && !collection.once_each {
            site_wide(Severity::Error, format!("The collection \"{name}\" has no fields."));
        }
        if collection.sealed {
            let shown = site.page_for(name).is_some()
                || site.any_block(&|b| {
                    matches!(b, Block::List { collection, .. } | Block::Count { collection, .. } if collection == name)
                });
            let tied = collection.parent.is_some() || site.collections.iter().any(|c| c.parent.as_deref() == Some(name.as_str()));
            if shown || tied || name == USERS || collection.once_each || collection.has_files() {
                site_wide(
                    Severity::Error,
                    format!("\"{name}\" is sealed, so only you can read it: it cannot be shown on the site, hold files, or be tied to other collections."),
                );
            }
        }
        if collection.once_each && !(collection.members_only && collection.parent.is_some()) {
            site_wide(
                Severity::Error,
                format!("\"{name}\" allows one record per member, so it must be members-only and belong to another collection."),
            );
        }
        if let Some(parent) = &collection.parent {
            if parent == name || site.collection(parent).is_none() {
                site_wide(Severity::Error, format!("The collection \"{name}\" belongs to \"{parent}\", which is not another collection."));
            }
        }
        let mut fields = BTreeSet::new();
        for field in &collection.fields {
            if !valid_slug(&field.name) {
                site_wide(
                    Severity::Error,
                    format!("A field of \"{name}\" has a name that is not lowercase letters, digits and dashes."),
                );
            } else if !fields.insert(field.name.as_str()) {
                site_wide(Severity::Error, format!("The collection \"{name}\" has two fields called \"{}\".", field.name));
            }
        }
        let shown = site.page_for(name).is_some()
            || site.any_block(&|b| matches!(b, Block::List { collection, .. } if collection == name));
        if name != USERS && site.has_form_for(name) && shown {
            site_wide(
                Severity::Warning,
                format!("Whatever visitors submit to \"{name}\" appears on the site without review."),
            );
        }
        if collection.fields.iter().any(|f| f.kind == FieldKind::Video) {
            site_wide(
                Severity::Warning,
                format!("Videos sent to \"{name}\" are stored as they arrive. Details a camera records inside the file are not removed."),
            );
        }
    }

    let mut seen = BTreeSet::new();
    for page in &site.pages {
        let mut add = |severity, message: String| {
            out.push(Finding { severity, page: page.slug.clone(), message });
        };
        if !valid_slug(&page.slug) {
            add(Severity::Error, "The page slug may only use lowercase letters, digits and dashes.".into());
        } else if !seen.insert(page.slug.as_str()) {
            add(Severity::Error, format!("More than one page uses the slug \"{}\".", page.slug));
        }
        if contains_email(&page.title) {
            add(Severity::Warning, "The page title contains an email address.".into());
        }
        let record = match &page.template {
            None => None,
            Some(_) if page.slug == HOME_SLUG => {
                add(Severity::Error, "The home page cannot be a template page.".into());
                None
            }
            Some(name) => {
                let found = site.collection(name);
                if found.is_none() {
                    add(
                        Severity::Error,
                        format!("This template page shows the collection \"{name}\", which does not exist."),
                    );
                }
                found
            }
        };
        lint_blocks(&page.blocks, &Scope { site, record }, &mut add);
    }
    out
}

fn lint_link(href: &str, scope: &Scope<'_>, add: &mut impl FnMut(Severity, String)) {
    match classify_link(href) {
        LinkTarget::Onion => {}
        LinkTarget::Clearnet => add(Severity::Warning, format!("The link \"{href}\" leaves Tor for the regular web.")),
        LinkTarget::Forbidden => {
            add(Severity::Error, format!("The link \"{href}\" is not a page path or an http(s) address."));
        }
        LinkTarget::Internal => {
            let path = href.trim().trim_start_matches('/');
            let (slug, to_record) = match path.strip_suffix(ID_TOKEN) {
                Some(rest) => (rest.trim_end_matches('/'), true),
                None => (if path.is_empty() { HOME_SLUG } else { path }, false),
            };
            let Some(page) = scope.site.pages.iter().find(|p| p.slug == slug) else {
                return add(Severity::Warning, format!("The link \"{href}\" points to a page that does not exist."));
            };
            match (&page.template, to_record) {
                (None, false) => {}
                (Some(_), false) => add(
                    Severity::Warning,
                    format!("The link \"{href}\" points to a template page without saying which record; end it with /{ID_TOKEN}."),
                ),
                (None, true) => {
                    add(Severity::Error, format!("The link \"{href}\" uses {ID_TOKEN}, but that page is not a template page."));
                }
                (Some(shown), true) => match scope.record {
                    None => {
                        add(Severity::Error, format!("The link \"{href}\" uses {ID_TOKEN} outside a list or template page."));
                    }
                    Some(here) if &here.name != shown => add(
                        Severity::Error,
                        format!("The link \"{href}\" opens a \"{shown}\" page from a \"{}\" record.", here.name),
                    ),
                    Some(_) => {}
                },
            }
        }
    }
}

fn lint_blocks(blocks: &[Block], scope: &Scope<'_>, add: &mut impl FnMut(Severity, String)) {
    let here = scope.record.map(|c| c.name.as_str());
    for block in blocks {
        match block {
            Block::Heading { text, .. } | Block::Text { text, .. } => {
                if contains_email(text) {
                    add(Severity::Warning, "Text contains an email address, which can identify you.".into());
                }
            }
            Block::Link { label, href, .. } => {
                if contains_email(label) {
                    add(Severity::Warning, "A link label contains an email address.".into());
                }
                lint_link(href, scope, add);
            }
            Block::Divider
            | Block::SignUp { .. }
            | Block::SignIn { .. }
            | Block::SignOut { .. }
            | Block::Search { .. } => {}
            Block::Count { collection, .. } => match (scope.site.collection(collection), scope.record) {
                (None, _) => {
                    add(Severity::Error, format!("A count is of the collection \"{collection}\", which does not exist."));
                }
                // Where no record is shown, it counts the whole collection.
                (Some(_), None) => {}
                (Some(counted), Some(shown)) => {
                    let hangs = counted.parent.as_deref() == Some(shown.name.as_str())
                        || (shown.name == USERS && counted.members_only);
                    if !hangs {
                        add(
                            Severity::Error,
                            format!("A count of \"{collection}\" is shown on a \"{}\" record, which they do not belong to.", shown.name),
                        );
                    }
                }
            },
            // On a members-only record its author sees the button; on any
            // record a moderator does.
            Block::Remove { .. } => {
                if scope.record.is_none() {
                    add(Severity::Error, "A remove button is shown where no record is being shown.".into());
                }
            }
            Block::Approve { .. } => match scope.record {
                None => add(Severity::Error, "An approve button is shown where no record is being shown.".into()),
                Some(collection) if !collection.review => {
                    add(Severity::Warning, format!("Nothing in \"{}\" waits for approval, so this button never shows.", collection.name));
                }
                Some(_) => {}
            },
            Block::Columns { columns } => {
                for column in columns {
                    lint_blocks(column, scope, add);
                }
            }
            Block::Gate { blocks, .. } => lint_blocks(blocks, scope, add),
            Block::Form { collection, .. } => match scope.site.collection(collection) {
                None => add(Severity::Error, format!("A form adds to the collection \"{collection}\", which does not exist.")),
                Some(_) if collection == USERS => {
                    add(Severity::Error, "Accounts are created with the Sign-up block, not a form.".into());
                }
                Some(target) => {
                    if let Some(parent) = &target.parent {
                        if here != Some(parent.as_str()) {
                            add(
                                Severity::Error,
                                format!("A form for \"{collection}\" must be on the template page of \"{parent}\", which each record belongs to."),
                            );
                        }
                    }
                }
            },
            Block::List { collection, limit, blocks, scope: which, .. } => {
                if !(1..=200).contains(limit) {
                    add(Severity::Error, "A list must show between 1 and 200 records.".into());
                }
                let record = scope.site.collection(collection);
                match (record, which) {
                    (None, _) => {
                        add(Severity::Error, format!("A list shows the collection \"{collection}\", which does not exist."));
                    }
                    (Some(_), ListScope::All) => {}
                    (Some(listed), ListScope::Children) => {
                        if listed.parent.as_deref().is_none() || listed.parent.as_deref() != here {
                            add(
                                Severity::Error,
                                format!("A list of the \"{collection}\" records of one record must be where a record they belong to is shown."),
                            );
                        }
                    }
                    (Some(listed), ListScope::Owned) => {
                        if !listed.members_only || here != Some(USERS) {
                            add(
                                Severity::Error,
                                format!("A list of one account's \"{collection}\" must be where an account is shown, and the collection must be members-only."),
                            );
                        }
                    }
                }
                lint_blocks(blocks, &Scope { site: scope.site, record }, add);
            }
            Block::Field { field, .. } => match scope.record {
                None => {
                    add(Severity::Error, format!("The field \"{field}\" is shown outside a list or template page."));
                }
                Some(collection) if collection.field(field).is_none() => {
                    add(Severity::Error, format!("The collection \"{}\" has no field called \"{field}\".", collection.name));
                }
                Some(_) => {}
            },
            Block::Author { .. } => {
                if !scope.record.is_some_and(|c| c.members_only) {
                    add(Severity::Error, "An author is shown where no members-only record is being shown.".into());
                }
            }
        }
    }
}

fn contains_email(text: &str) -> bool {
    text.split_whitespace().any(|word| {
        let Some((local, domain)) = word.split_once('@') else { return false };
        let local_ok = local.chars().last().is_some_and(char::is_alphanumeric);
        let domain_ok = domain.split_once('.').is_some_and(|(name, tld)| {
            name.chars().next().is_some_and(char::is_alphanumeric)
                && tld.chars().next().is_some_and(char::is_alphanumeric)
        });
        local_ok && domain_ok
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_links() {
        assert_eq!(classify_link("/about"), LinkTarget::Internal);
        assert_eq!(classify_link("http://abc.onion/x"), LinkTarget::Onion);
        assert_eq!(classify_link("HTTPS://ABC.ONION:8080"), LinkTarget::Onion);
        assert_eq!(classify_link("https://example.com"), LinkTarget::Clearnet);
        assert_eq!(classify_link("https://abc.onion.example.com"), LinkTarget::Clearnet);
        assert_eq!(classify_link("//example.com"), LinkTarget::Forbidden);
        assert_eq!(classify_link("javascript:alert(1)"), LinkTarget::Forbidden);
        assert_eq!(classify_link("http://abc.onion@example.com"), LinkTarget::Forbidden);
        assert_eq!(classify_link("mailto:me@example.com"), LinkTarget::Forbidden);
    }

    #[test]
    fn spots_emails() {
        assert!(contains_email("write to me@example.com today"));
        assert!(!contains_email("meet @ noon"));
        assert!(!contains_email("user@localhost"));
    }
}
