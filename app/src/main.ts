import { invoke, isTauri } from "@tauri-apps/api/core";

// Mirrors the model in crates/core. `id` is editor-only; the compiler ignores it.
type Align = "left" | "center" | "right";
type Block = { id: string } & (
  | { type: "heading"; level: number; text: string; align: Align }
  | { type: "text"; text: string; align: Align }
  | { type: "link"; label: string; href: string; align: Align }
  | { type: "divider" }
  | { type: "columns"; columns: Block[][] }
  | { type: "form"; collection: string; submit_label: string }
  | {
      type: "list";
      collection: string;
      newest_first: boolean;
      limit: number;
      blocks: Block[];
      layout: "rows" | "grid";
      scope: "all" | "children" | "owned";
      active_first: boolean;
      paged: boolean;
    }
  | { type: "search"; label: string }
  | { type: "count"; collection: string; label: string; align: Align }
  | { type: "remove"; label: string }
  | { type: "approve"; label: string }
  | { type: "field"; field: string; level: number; align: Align; preview: boolean }
  | { type: "author"; align: Align }
  | { type: "sign_up" | "sign_in" | "sign_out"; submit_label: string }
  | { type: "gate"; audience: "members" | "guests"; blocks: Block[] }
);
type BlockType = Block["type"];
type Field = { name: string; label: string; kind: "text" | "long_text" | "image" | "video"; required: boolean };
type Collection = {
  name: string;
  fields: Field[];
  parent: string | null;
  members_only: boolean;
  once_each: boolean;
  sealed: boolean;
  review?: boolean;
};
// The collection that holds accounts, and its name field. Both are fixed by the site model.
const USERS = "users";
const USER_NAME = "name";
type Page = { slug: string; title: string; blocks: Block[]; template: string | null };
type Site = {
  title: string;
  theme: { accent: string; dark: boolean };
  pages: Page[];
  collections: Collection[];
  accounts: boolean;
  // Filled in by the backend when publishing.
  seal_key?: string | null;
  // How much room visitors' files may take, in megabytes.
  limits?: { video_mb: number; storage_mb: number; sizes?: boolean; shrink?: boolean };
};
// A record as the running site stores it.
type Stored = { id: string; fields: Record<string, string>; held?: boolean };
type Finding = { severity: "error" | "warning"; page: string; message: string };
type View = { canvas: { css: string; html: string } | null; findings: Finding[] };

const LABELS: Record<BlockType, string> = {
  heading: "Heading",
  text: "Text",
  link: "Link button",
  divider: "Divider",
  columns: "Columns",
  form: "Form",
  list: "List of records",
  field: "Record field",
  author: "Author of record",
  sign_up: "Sign-up form",
  sign_in: "Sign-in form",
  sign_out: "Sign-out button",
  gate: "Members or guests only",
  search: "Search box",
  count: "Count of records",
  remove: "Delete-my-own button",
  approve: "Approve button for moderators",
};

// Editing aids layered over the published stylesheet. Nothing here is published.
const EDITOR_CSS = `
.page{flex:1;min-width:0}
main[data-list]{min-height:60vh}
[data-b]{cursor:grab}
[data-b]:hover{outline:1px dashed #9b5fb8;outline-offset:2px}
[data-b].selected{outline:2px solid #9b5fb8;outline-offset:2px}
a,form{pointer-events:none}
.columns>[data-list],article[data-list]{min-height:3rem}
[data-list].empty{outline:1px dashed #8888;border-radius:6px}
main.empty::before{content:"Drag a block here";display:block;padding:2rem;text-align:center;opacity:.6}
article.empty::before{content:"Drag blocks here: they repeat for every record";display:block;padding:.75rem;text-align:center;opacity:.6}
.gate{min-height:3rem;outline:1px dotted #8888;outline-offset:2px;border-radius:6px}
.gate.empty::before{content:"Drag blocks here: only some visitors see them";display:block;padding:.75rem;text-align:center;opacity:.6}
.marker{height:0;outline:2px solid #9b5fb8;pointer-events:none}
`;

let nextId = 1;
const newId = () => `b${nextId++}`;

// Lowercase letters, digits and dashes: the only names the site model accepts.
const slug = (text: string) =>
  text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);

// Forms and lists need a collection, so the first one is made for them.
function someCollection(): string {
  const existing = site.collections.find((c) => c.name !== USERS);
  if (existing) return existing.name;
  site.collections.push({
    name: "notes",
    parent: null,
    members_only: false,
    once_each: false,
    sealed: false,
    fields: [
      { name: "name", label: "Name", kind: "text", required: true },
      { name: "message", label: "Message", kind: "long_text", required: false },
    ],
  });
  return "notes";
}

// Accounts are the records of one fixed collection, made when they are first needed.
function enableAccounts() {
  site.accounts = true;
  if (!site.collections.some((c) => c.name === USERS)) {
    site.collections.unshift({
      name: USERS,
      parent: null,
      members_only: false,
      once_each: false,
      sealed: false,
      fields: [{ name: USER_NAME, label: "Name", kind: "text", required: true }],
    });
  }
}

function create(type: BlockType): Block {
  const id = newId();
  switch (type) {
    case "heading":
      return { id, type, level: 2, text: "Heading", align: "left" };
    case "text":
      return { id, type, text: "Write something.", align: "left" };
    case "link":
      return { id, type, label: "Read more", href: "/", align: "left" };
    case "divider":
      return { id, type };
    case "columns":
      return { id, type, columns: [[], []] };
    case "form":
      return { id, type, collection: someCollection(), submit_label: "Send" };
    case "list":
      return {
        id,
        type,
        collection: someCollection(),
        newest_first: true,
        limit: 20,
        blocks: [],
        layout: "rows",
        scope: "all",
        active_first: false,
        paged: true,
      };
    case "search":
      return { id, type, label: "Search" };
    case "count":
      return { id, type, collection: someCollection(), label: "in total", align: "left" };
    case "remove":
      enableAccounts();
      return { id, type, label: "Delete" };
    case "approve":
      enableAccounts();
      return { id, type, label: "Approve" };
    case "field":
      return { id, type, field: "", level: 0, align: "left", preview: false };
    case "author":
      enableAccounts();
      return { id, type, align: "left" };
    case "sign_up":
      enableAccounts();
      return { id, type, submit_label: "Create account" };
    case "sign_in":
      enableAccounts();
      return { id, type, submit_label: "Sign in" };
    case "sign_out":
      enableAccounts();
      return { id, type, submit_label: "Sign out" };
    case "gate":
      enableAccounts();
      return { id, type, audience: "members", blocks: [] };
  }
}

function blankSite(title: string): Site {
  return {
    title,
    theme: { accent: "#7d4698", dark: true },
    collections: [],
    accounts: false,
    pages: [
      {
        slug: "index",
        title: "Home",
        template: null,
        blocks: [
          { id: newId(), type: "heading", level: 1, text: "Welcome", align: "left" },
          { id: newId(), type: "text", text: "Drag blocks from the left onto this page.", align: "left" },
        ],
      },
    ],
  };
}

// Every site in the vault. `address` is its onion address once it has one.
type Entry = { id: number; site: Site; address: string | null };
let entries: Entry[] = [{ id: 0, site: blankSite("My onion site"), address: null }];
let current = entries[0];
// The site being edited.
let site = current.site;
let pageIndex = 0;
let selectedId: string | null = null;
let drag: { kind: "new"; type: BlockType } | { kind: "move"; id: string } | null = null;

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const inspector = $("inspector");
const status = $("status");

function el<K extends keyof HTMLElementTagNameMap>(tag: K, className = "", text = "") {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text) node.textContent = text;
  return node;
}

// The canvas is the published page itself, rendered into a shadow root so the
// site's stylesheet and the editor's cannot affect each other.
const shadow = $("canvas").attachShadow({ mode: "open" });
const sheet = el("style");
const pageEl = el("div", "page");
const marker = el("div", "marker");
shadow.append(sheet, pageEl);

const page = () => site.pages[pageIndex];

// The lists of blocks a block holds: a column each, or a list's repeated blocks.
function childLists(block: Block): Block[][] {
  if (block.type === "columns") return block.columns;
  if (block.type === "list" || block.type === "gate") return [block.blocks];
  return [];
}

// Paths come from the compiler: dot-separated indexes, alternating block and child list.
function walk(path: string): { list: Block[]; index: number | null } | null {
  let list = page().blocks;
  const steps = path === "" ? [] : path.split(".").map(Number);
  for (let i = 0; i < steps.length; i += 2) {
    const block = list[steps[i]];
    if (!block) return null;
    if (i === steps.length - 1) return { list, index: steps[i] };
    const next = childLists(block)[steps[i + 1]];
    if (!next) return null;
    list = next;
  }
  return { list, index: null };
}

// Also reports which collection's record is being shown where the block
// stands: the enclosing list's, or the template page's.
function locate(
  id: string,
  blocks = page().blocks,
  prefix = "",
  record = page().template,
): { list: Block[]; index: number; path: string; record: string | null } | null {
  for (let index = 0; index < blocks.length; index++) {
    const block = blocks[index];
    const path = prefix + index;
    if (block.id === id) return { list: blocks, index, path, record };
    const inside = block.type === "list" ? block.collection : record;
    const lists = childLists(block);
    for (let c = 0; c < lists.length; c++) {
      const found = locate(id, lists[c], `${path}.${c}.`, inside);
      if (found) return found;
    }
  }
  return null;
}

function contains(block: Block, list: Block[]): boolean {
  return childLists(block).some((own) => own === list || own.some((child) => contains(child, list)));
}

// Every block of the site, however deeply nested.
function everyBlock(visit: (block: Block) => void, blocks?: Block[]) {
  for (const block of blocks ?? site.pages.flatMap((p) => p.blocks)) {
    visit(block);
    childLists(block).forEach((own) => everyBlock(visit, own));
  }
}

// Canvas

let renderSeq = 0;
async function render() {
  const seq = ++renderSeq;
  if (!isTauri()) {
    pageEl.textContent = "The canvas needs the desktop app.";
    return;
  }
  const view = await invoke<View>("canvas", { site, slug: page().slug });
  // A newer edit is already being rendered.
  if (seq !== renderSeq) return;
  sheet.textContent = (view.canvas?.css ?? "") + EDITOR_CSS;
  pageEl.innerHTML = view.canvas?.html ?? "";
  for (const block of pageEl.querySelectorAll<HTMLElement>("[data-b]")) block.draggable = true;
  for (const list of pageEl.querySelectorAll<HTMLElement>("[data-list]")) {
    list.classList.toggle("empty", !list.querySelector(":scope > [data-b]"));
  }
  const selected = selectedId ? locate(selectedId) : null;
  if (selected) pageEl.querySelector(`[data-b="${selected.path}"]`)?.classList.add("selected");
  showFindings(view.findings);
}

function blockUnder(event: Event) {
  const tagged = (event.target as HTMLElement).closest<HTMLElement>("[data-b]");
  const found = tagged ? walk(tagged.dataset.b!) : null;
  return found && found.index !== null ? found.list[found.index] : null;
}

pageEl.addEventListener("click", (event) => {
  // Never follow the page's own links inside the editor.
  event.preventDefault();
  selectedId = blockUnder(event)?.id ?? null;
  refresh();
  // On a phone the settings of the block sit below the page, so bring them into view.
  if (selectedId && matchMedia("(max-width: 800px)").matches) {
    $("selected").scrollIntoView({ behavior: "smooth", block: "start" });
  }
});

pageEl.addEventListener("dragstart", (event) => {
  const block = blockUnder(event);
  if (!block || !event.dataTransfer) return;
  drag = { kind: "move", id: block.id };
  event.dataTransfer.effectAllowed = "move";
  event.dataTransfer.setData("text/plain", "");
});

// The list under the pointer and the position in it, judged by block midpoints.
function dropTarget(event: DragEvent) {
  const host =
    (event.target as HTMLElement).closest<HTMLElement>("[data-list]") ??
    pageEl.querySelector<HTMLElement>("main[data-list]");
  const list = host ? walk(host.dataset.list!)?.list : null;
  if (!host || !list) return null;
  const blocks = [...host.querySelectorAll<HTMLElement>(":scope > [data-b]")];
  let index = blocks.findIndex((block) => {
    const box = block.getBoundingClientRect();
    return event.clientY < box.top + box.height / 2;
  });
  if (index < 0) index = blocks.length;
  return { host, list, index, before: blocks[index] ?? null };
}

pageEl.addEventListener("dragover", (event) => {
  const target = drag && dropTarget(event);
  if (!target) return;
  event.preventDefault();
  target.host.insertBefore(marker, target.before);
});

pageEl.addEventListener("drop", (event) => {
  const target = drag && dropTarget(event);
  if (!drag || !target) return;
  event.preventDefault();
  const { list } = target;
  let index = target.index;
  let block: Block;
  if (drag.kind === "new") {
    block = create(drag.type);
  } else {
    const from = locate(drag.id);
    // A block cannot be dropped inside itself.
    if (!from || contains(from.list[from.index], list)) return endDrag();
    [block] = from.list.splice(from.index, 1);
    if (from.list === list && from.index < index) index--;
  }
  list.splice(index, 0, block);
  selectedId = block.id;
  endDrag();
  refresh();
});

function endDrag() {
  drag = null;
  marker.remove();
}
document.addEventListener("dragend", endDrag);

function removeSelected() {
  const found = selectedId ? locate(selectedId) : null;
  if (!found) return;
  found.list.splice(found.index, 1);
  selectedId = null;
  refresh();
}

document.addEventListener("keydown", (event) => {
  const typing = (event.target as HTMLElement).closest("input, textarea, select");
  if (event.key === "Delete" && !typing) removeSelected();
});

// Palette

for (const type of Object.keys(LABELS) as BlockType[]) {
  const item = el("div", "palette-item", LABELS[type]);
  item.draggable = true;
  item.addEventListener("dragstart", (event) => {
    drag = { kind: "new", type };
    event.dataTransfer!.effectAllowed = "copy";
    event.dataTransfer!.setData("text/plain", "");
  });
  // Double-click appends, for when dragging is awkward. On a touch screen,
  // where there is no dragging at all, a single tap does.
  const append = () => {
    const block = create(type);
    page().blocks.push(block);
    selectedId = block.id;
    refresh();
  };
  item.addEventListener("dblclick", append);
  item.addEventListener("click", () => {
    if (matchMedia("(pointer: coarse)").matches) append();
  });
  $("palette").append(item);
}

// Inspector and settings

function field(label: string, control: HTMLElement) {
  const wrap = el("label", "field");
  wrap.append(el("span", "", label), control);
  return wrap;
}

function textInput(value: string, onChange: (value: string) => void, multiline = false) {
  const input = multiline ? el("textarea") : el("input");
  input.value = value;
  input.addEventListener("input", () => {
    onChange(input.value);
    changed();
  });
  return input;
}

function choice<T>(options: [T, string][], value: T, onChange: (value: T) => void) {
  const select = el("select");
  options.forEach(([, label], index) => select.append(new Option(label, String(index))));
  select.value = String(options.findIndex(([option]) => option === value));
  select.addEventListener("change", () => {
    onChange(options[Number(select.value)][0]);
    changed();
  });
  return select;
}

const alignField = (block: { align: Align }) =>
  field(
    "Position",
    choice<Align>([["left", "Left"], ["center", "Middle"], ["right", "Right"]], block.align, (v) => (block.align = v)),
  );

function flag(value: boolean, onChange: (value: boolean) => void) {
  const box = el("input");
  box.type = "checkbox";
  box.checked = value;
  box.addEventListener("change", () => {
    onChange(box.checked);
    changed();
  });
  return box;
}

function renderInspector() {
  inspector.replaceChildren();
  const found = selectedId ? locate(selectedId) : null;
  if (!found) {
    inspector.append(el("p", "hint", "Click a block on the page to edit it."));
    return;
  }
  const block = found.list[found.index];
  switch (block.type) {
    case "heading":
      inspector.append(
        field("Text", textInput(block.text, (v) => (block.text = v))),
        field(
          "Size",
          choice([1, 2, 3, 4, 5, 6].map((n): [number, string] => [n, `Level ${n}`]), block.level, (v) => (block.level = v)),
        ),
        alignField(block),
      );
      break;
    case "text":
      inspector.append(field("Text", textInput(block.text, (v) => (block.text = v), true)), alignField(block));
      break;
    case "link":
      inspector.append(
        field("Label", textInput(block.label, (v) => (block.label = v))),
        field("Address", textInput(block.href, (v) => (block.href = v))),
        alignField(block),
      );
      break;
    case "columns": {
      const add = el("button", "", "Add column");
      add.disabled = block.columns.length >= 4;
      add.addEventListener("click", () => {
        block.columns.push([]);
        refresh();
      });
      const drop = el("button", "", "Remove last column");
      drop.disabled = block.columns.length <= 2;
      drop.addEventListener("click", () => {
        block.columns.pop();
        refresh();
      });
      inspector.append(add, drop);
      break;
    }
    case "form":
      inspector.append(
        field("Adds to", collectionChoice(block.collection, (v) => (block.collection = v))),
        field("Button label", textInput(block.submit_label, (v) => (block.submit_label = v))),
        el("p", "hint", "Its inputs are the collection's fields. Edit them under Collections."),
      );
      break;
    case "list": {
      const limit = el("input");
      limit.value = String(block.limit);
      limit.addEventListener("input", () => {
        block.limit = Math.min(200, Math.max(1, Math.floor(Number(limit.value)) || 1));
        changed();
      });
      limit.type = "number";
      limit.min = "1";
      limit.max = "200";
      inspector.append(
        field("Shows", collectionChoice(block.collection, (v) => (block.collection = v))),
        field(
          "Order",
          choice<boolean>([[true, "Newest first"], [false, "Oldest first"]], block.newest_first, (v) => (block.newest_first = v)),
        ),
        field("At most", limit),
        field("Further pages", flag(block.paged, (v) => (block.paged = v))),
        field("Recently replied-to first", flag(block.active_first, (v) => (block.active_first = v))),
        field(
          "Laid out as",
          choice<"rows" | "grid">([["rows", "Rows"], ["grid", "Cards side by side"]], block.layout, (v) => (block.layout = v)),
        ),
        field(
          "Which ones",
          choice<"all" | "children" | "owned">(
            [
              ["all", "All of them"],
              ["children", "Those belonging to the record shown"],
              ["owned", "Those added by the account shown"],
            ],
            block.scope,
            (v) => (block.scope = v),
          ),
        ),
        el("p", "hint", "Blocks dropped inside repeat for every record. Use Record field blocks to show its values."),
      );
      break;
    }
    case "field": {
      const shown = site.collections.find((c) => c.name === found.record);
      if (!shown) {
        inspector.append(el("p", "hint", "Move this block into a list, or onto a template page, to choose a field."));
        break;
      }
      const options = shown.fields.map((f): [string, string] => [f.name, f.label]);
      inspector.append(
        field("Field", choice<string>([["", "Choose a field"], ...options], block.field, (v) => (block.field = v))),
        field(
          "Shown as",
          choice([0, 1, 2, 3, 4, 5, 6].map((n): [number, string] => [n, n ? `Heading ${n}` : "Text"]), block.level, (v) => (block.level = v)),
        ),
        alignField(block),
      );
      if (shown.fields.find((f) => f.name === block.field)?.kind === "video") {
        inspector.append(
          field("Show a still frame, not a player", flag(block.preview, (v) => (block.preview = v))),
          el("p", "hint", "For cards in a list. The frame is taken from the video itself."),
        );
      }
      break;
    }
    case "author":
      inspector.append(alignField(block), el("p", "hint", "Shows who added the record, linking to the page that shows accounts."));
      break;
    case "search":
      inspector.append(
        field("Button label", textInput(block.label, (v) => (block.label = v))),
        el("p", "hint", "Narrows the lists on this page that show a whole collection."),
      );
      break;
    case "count":
      inspector.append(
        field("Counts", collectionChoice(block.collection, (v) => (block.collection = v))),
        field("Words after the number", textInput(block.label, (v) => (block.label = v))),
        alignField(block),
        el("p", "hint", "Where a record is shown, it counts what belongs to that record."),
      );
      break;
    case "remove":
      inspector.append(
        field("Button label", textInput(block.label, (v) => (block.label = v))),
        el("p", "hint", "The member who added the record sees this button, and so do moderators."),
      );
      break;
    case "approve":
      inspector.append(
        field("Button label", textInput(block.label, (v) => (block.label = v))),
        el("p", "hint", "Only moderators see this, and only on a record that is waiting for approval. Turn on waiting in the collection's settings."),
      );
      break;
    case "sign_up":
    case "sign_in":
    case "sign_out":
      inspector.append(field("Button label", textInput(block.submit_label, (v) => (block.submit_label = v))));
      if (block.type === "sign_up") inspector.append(el("p", "hint", "Asks for the fields of the users collection and a password."));
      break;
    case "gate":
      inspector.append(
        field(
          "Shown to",
          choice<"members" | "guests">(
            [["members", "Signed-in visitors"], ["guests", "Visitors who are not signed in"]],
            block.audience,
            (v) => (block.audience = v),
          ),
        ),
      );
      break;
    case "divider":
  }
  if (block.type === "link" && found.record) {
    const template = site.pages.find((p) => p.template === found.record);
    const example = template ? `/${template.slug}/{id}` : "/page/{id}";
    inspector.append(el("p", "hint", `To open this record's own page, use an address like ${example}.`));
  }
  // Moving without dragging, which is the only way on a touch screen.
  const move = (by: number) => {
    const to = found.index + by;
    if (to < 0 || to >= found.list.length) return;
    found.list.splice(to, 0, found.list.splice(found.index, 1)[0]);
    refresh();
  };
  const up = el("button", "", "Move up");
  up.disabled = found.index === 0;
  up.addEventListener("click", () => move(-1));
  const down = el("button", "", "Move down");
  down.disabled = found.index === found.list.length - 1;
  down.addEventListener("click", () => move(1));
  const remove = el("button", "", "Delete block");
  remove.addEventListener("click", removeSelected);
  inspector.append(up, down, remove);
}

function renderSettings() {
  const host = $("page-settings");
  host.replaceChildren();
  const current = page();
  const isHome = current.slug === "index";

  const address = textInput(current.slug, (v) => (current.slug = v));
  address.disabled = isHome;
  // A template page is designed once and shown for every record of a collection.
  const template = choice<string | null>(
    [[null, "No: an ordinary page"], ...site.collections.map((c): [string, string] => [c.name, `Each record of ${c.name}`])],
    current.template,
    (v) => {
      current.template = v;
      renderInspector();
    },
  );
  template.disabled = isHome || site.collections.length === 0;
  const accent = el("input");
  accent.type = "color";
  accent.value = site.theme.accent;
  accent.addEventListener("input", () => {
    site.theme.accent = accent.value;
    changed();
  });
  const dark = el("input");
  dark.type = "checkbox";
  dark.checked = site.theme.dark;
  dark.addEventListener("change", () => {
    site.theme.dark = dark.checked;
    changed();
  });
  // What belongs to this page goes with the page; what belongs to the whole
  // site goes further down, where it is out of the way.
  const siteHost = $("site-settings");
  siteHost.replaceChildren();
  host.append(
    field("Page title", textInput(current.title, (v) => (current.title = v))),
    field("Page address", address),
    field("Template page", template),
  );
  siteHost.append(field("Accent colour", accent), field("Dark theme", dark));
  if (!isHome) {
    const remove = el("button", "", "Delete page");
    remove.addEventListener("click", () => {
      site.pages.splice(pageIndex, 1);
      pageIndex = 0;
      selectedId = null;
      refresh();
    });
    host.append(remove);
  }
  const accounts = el("input");
  accounts.type = "checkbox";
  accounts.checked = site.accounts;
  accounts.addEventListener("change", () => {
    if (accounts.checked) enableAccounts();
    else site.accounts = false;
    refresh();
  });
  siteHost.append(field("Visitors can create accounts", accounts));

  // How much of this device visitors' files may fill.
  const limits = (site.limits ??= { video_mb: 300, storage_mb: 5120 });
  const megabytes = (value: number, most: number, set: (v: number) => void) => {
    const input = el("input");
    input.type = "number";
    input.min = "1";
    input.max = String(most);
    input.value = String(value);
    input.addEventListener("change", () => {
      const typed = Math.round(Number(input.value));
      set(Math.min(most, Math.max(1, Number.isFinite(typed) ? typed : 1)));
      refresh();
    });
    return input;
  };
  siteHost.append(
    field("Largest video (MB, up to 10 GB)", megabytes(limits.video_mb, 10240, (v) => (limits.video_mb = v))),
    field("Room for all files (MB)", megabytes(limits.storage_mb, 1048576, (v) => (limits.storage_mb = v))),
  );
  // What the converter makes from uploaded videos, where this device has one.
  const toggle = (on: boolean, set: (v: boolean) => void) => {
    const input = el("input");
    input.type = "checkbox";
    input.checked = on;
    input.addEventListener("change", () => {
      set(input.checked);
      refresh();
    });
    return input;
  };
  siteHost.append(
    field("Make 360p and 720p copies", toggle(limits.sizes ?? true, (v) => (limits.sizes = v))),
    el(
      "p",
      "hint",
      "Every uploaded video is encoded afresh, in a sandbox with no network and no files, before anyone can watch it: nothing the camera or phone recorded about it survives. Large videos take a while to appear. Leave room for twice the largest video while one is being prepared.",
    ),
  );

  // Replaces every page and collection, so it also takes two clicks.
  const kinds: [string, string][] = [["video", "Video site"], ["board", "Anonymous board"], ["microblog", "Microblog"]];
  const kind = el("select");
  for (const [value, label] of kinds) kind.append(new Option(label, value));
  siteHost.append(field("Ready-made site", kind));
  const starter = el("button", "", "Start over from it");
  starter.addEventListener("click", async () => {
    if (!starter.dataset.armed) {
      starter.dataset.armed = "1";
      starter.textContent = "Click again: replaces all pages of this site";
      return;
    }
    try {
      const fresh = await invoke<Site>("starter", { kind: kind.value });
      fresh.pages.forEach((p) => withIds(p.blocks));
      Object.assign(site, fresh, { title: site.title, theme: site.theme });
      pageIndex = 0;
      selectedId = null;
      refresh();
    } catch (error) {
      showFailure(error);
    }
  });
  siteHost.append(starter);

  // Deleting a site destroys its onion key, so it takes two deliberate clicks.
  const erase = el("button", "", "Delete site");
  erase.disabled = entries.length < 2;
  erase.addEventListener("click", () => {
    if (erase.dataset.armed) return void deleteCurrent();
    erase.dataset.armed = "1";
    erase.textContent = "Click again: erases the site and its address forever";
  });
  siteHost.append(erase);
}

// Collections

function collectionChoice(value: string, onChange: (value: string) => void) {
  const options = site.collections.map((c): [string, string] => [c.name, c.name]);
  if (!site.collections.some((c) => c.name === value)) options.unshift([value, value ? `${value} (missing)` : "Choose"]);
  return choice<string>(options, value, onChange);
}

// Renaming a collection must carry every form, list and template page with it.
function renameCollection(collection: Collection, name: string) {
  const old = collection.name;
  collection.name = name;
  for (const p of site.pages) if (p.template === old) p.template = name;
  everyBlock((block) => {
    if ((block.type === "form" || block.type === "list") && block.collection === old) block.collection = name;
  });
}

function unusedName(wanted: string, taken: string[]) {
  let name = wanted || "item";
  for (let n = 2; taken.includes(name); n++) name = `${wanted || "item"}-${n}`;
  return name;
}

function renderCollections() {
  const host = $("collections");
  host.replaceChildren();
  if (site.collections.length === 0) {
    host.append(el("p", "hint", "A collection holds what visitors submit: posts, comments, sign-ups."));
  }
  for (const collection of site.collections) {
    const box = el("div", "collection");
    const name = el("input");
    name.value = collection.name;
    name.title = "Collection name";
    // Applied when editing ends, so half-typed names are never propagated.
    name.addEventListener("change", () => {
      const others = site.collections.filter((c) => c !== collection).map((c) => c.name);
      renameCollection(collection, unusedName(slug(name.value), others));
      refresh();
    });
    box.append(name);
    if (collection.name === USERS) {
      name.disabled = true;
      box.append(el("p", "hint", "One record per account. People sign up with these fields and a password."));
    } else {
      const others = site.collections.filter((c) => c !== collection && c.name !== USERS);
      const parent = choice<string | null>(
        [[null, "Stands alone"], ...others.map((c): [string, string] => [c.name, `Belongs to a record of ${c.name}`])],
        collection.parent,
        (v) => (collection.parent = v),
      );
      const members = el("input");
      members.type = "checkbox";
      members.checked = collection.members_only;
      members.addEventListener("change", () => {
        collection.members_only = members.checked;
        if (members.checked) enableAccounts();
        refresh();
      });
      box.append(
        field("Each record", parent),
        field("Only signed-in visitors can add", members),
        field("One per member, like a vote or a like", flag(collection.once_each, (v) => (collection.once_each = v))),
        field("Sealed: only you can read it, not even the site", flag(collection.sealed, (v) => (collection.sealed = v))),
        field("Hold new entries until approved", flag(collection.review ?? false, (v) => (collection.review = v))),
      );
    }

    for (const item of collection.fields) {
      const row = el("div", "field-row");
      const label = textInput(item.label, (v) => (item.label = v));
      label.title = "What visitors see next to this input";
      const kinds: [Field["kind"], string][] = [["text", "Short"], ["long_text", "Long"], ["image", "Picture"], ["video", "Video"]];
      const kind = choice<Field["kind"]>(kinds, item.kind, (v) => (item.kind = v));
      // The name of an account is what it signs in with, so it stays as it is.
      const fixed = collection.name === USERS && item.name === USER_NAME;
      kind.disabled = fixed;
      const required = el("input");
      required.type = "checkbox";
      required.checked = item.required;
      required.title = "Required";
      required.addEventListener("change", () => {
        item.required = required.checked;
        changed();
      });
      const remove = el("button", "", "×");
      remove.title = "Remove field";
      remove.disabled = collection.fields.length < 2 || fixed;
      required.disabled = fixed;
      remove.addEventListener("click", () => {
        collection.fields.splice(collection.fields.indexOf(item), 1);
        refresh();
      });
      row.append(label, kind, required, remove);
      box.append(row);
    }

    const add = el("button", "", "Add field");
    add.addEventListener("click", () => {
      const label = `Field ${collection.fields.length + 1}`;
      const taken = collection.fields.map((f) => f.name);
      collection.fields.push({ name: unusedName(slug(label), taken), label, kind: "text", required: false });
      refresh();
    });
    const remove = el("button", "", "Delete collection");
    remove.disabled = collection.name === USERS && site.accounts;
    remove.addEventListener("click", () => {
      site.collections.splice(site.collections.indexOf(collection), 1);
      for (const other of site.collections) if (other.parent === collection.name) other.parent = null;
      refresh();
    });
    // What visitors have added, fetched from the running site on request.
    const show = el("button", "", "Show what visitors added");
    const list = el("div", "records");
    const load = async () => {
      list.replaceChildren();
      try {
        const records = await invoke<Stored[]>("records", { id: current.id, collection: collection.name });
        const accounts = collection.name === USERS;
        let moderators = accounts ? await invoke<string[]>("moderators", { id: current.id }) : [];
        if (records.length === 0) list.append(el("p", "hint", "Nothing yet."));
        if (accounts && records.length > 0) {
          list.append(el("p", "hint", "A moderator sees a Remove button wherever a page has a Remove block, and can remove what anyone added."));
        }
        for (const record of [...records].reverse()) {
          const row = el("div", "record");
          const words = collection.fields
            .filter((f) => f.kind === "text" || f.kind === "long_text")
            .map((f) => record.fields[f.name])
            .filter(Boolean)
            .join(" · ");
          row.append(el("span", "", words.slice(0, 120) || "(files only)"));
          if (record.held) {
            const approve = el("button", "", "Approve");
            approve.addEventListener("click", async () => {
              await invoke("approve_record", { id: current.id, collection: collection.name, record: record.id });
              void load();
            });
            row.append(el("span", "hint", "waiting"), approve);
          }
          if (accounts) {
            const staff = el("button", "", moderators.includes(record.id) ? "Moderator ✓" : "Make moderator");
            staff.addEventListener("click", async () => {
              const on = !moderators.includes(record.id);
              moderators = await invoke<string[]>("set_moderator", { id: current.id, account: record.id, on });
              staff.textContent = moderators.includes(record.id) ? "Moderator ✓" : "Make moderator";
            });
            row.append(staff);
          }
          const erase = el("button", "", "Remove");
          erase.addEventListener("click", async () => {
            // Removal cannot be undone, so it takes two clicks.
            if (!erase.dataset.armed) {
              erase.dataset.armed = "1";
              erase.textContent = "Remove for good?";
              return;
            }
            await invoke("remove_record", { id: current.id, collection: collection.name, record: record.id });
            void load();
          });
          row.append(erase);
          list.append(row);
        }
      } catch (error) {
        list.append(el("p", "hint", (error as Failure).message ?? "Could not fetch them."));
      }
    };
    show.addEventListener("click", load);
    box.append(add, remove, show, list);
    host.append(box);
  }
  const add = el("button", "", "Add collection");
  add.addEventListener("click", () => {
    const taken = site.collections.map((c) => c.name);
    site.collections.push({
      name: unusedName("collection", taken),
      parent: null,
      members_only: false,
      once_each: false,
      sealed: false,
      fields: [{ name: "text", label: "Text", kind: "text", required: true }],
    });
    refresh();
  });
  host.append(add);
}

function renderPages() {
  const host = $("pages");
  host.replaceChildren();
  site.pages.forEach((p, index) => {
    const tab = el("button", "tab", p.title || p.slug);
    tab.classList.toggle("active", index === pageIndex);
    tab.addEventListener("click", () => {
      pageIndex = index;
      selectedId = null;
      refresh();
    });
    host.append(tab);
  });
}

$("add-page").addEventListener("click", () => {
  let n = site.pages.length + 1;
  while (site.pages.some((p) => p.slug === `page-${n}`)) n++;
  site.pages.push({ slug: `page-${n}`, title: `Page ${n}`, blocks: [], template: null });
  pageIndex = site.pages.length - 1;
  selectedId = null;
  refresh();
});

const title = $<HTMLInputElement>("site-title");
title.addEventListener("input", () => {
  site.title = title.value;
  renderSites();
  changed();
});

// Sites

const picker = $<HTMLSelectElement>("sites");

function renderSites() {
  picker.replaceChildren(...entries.map((entry) => new Option(entry.site.title || "Untitled site", String(entry.id))));
  picker.value = String(current.id);
}

function open(entry: Entry) {
  flushSave();
  current = entry;
  site = entry.site;
  pageIndex = 0;
  selectedId = null;
  note = "";
  title.value = site.title;
  renderSites();
  showStatus();
  refresh();
}

picker.addEventListener("change", () => {
  const entry = entries.find((e) => String(e.id) === picker.value);
  if (entry) open(entry);
});

$("add-site").addEventListener("click", async () => {
  const fresh = blankSite(`Site ${entries.length + 1}`);
  try {
    const entry = { id: await invoke<number>("add_site", { site: fresh }), site: fresh, address: null };
    entries.push(entry);
    open(entry);
  } catch (error) {
    showFailure(error);
  }
});

async function deleteCurrent() {
  try {
    await invoke("delete_site", { id: current.id });
  } catch (error) {
    return showFailure(error);
  }
  clearTimeout(saveTimer);
  saveTimer = 0;
  entries = entries.filter((entry) => entry !== current);
  current = entries[0];
  open(current);
}

// Checks and publishing

function showFindings(findings: Finding[]) {
  const host = $("findings");
  host.replaceChildren();
  if (findings.length === 0) host.append(el("li", "ok", "No problems found."));
  for (const finding of findings) {
    const where = finding.page ? `${finding.page}: ` : "";
    host.append(el("li", finding.severity, where + finding.message));
  }
}

type Failure = { message: string; findings: Finding[] };

function showFailure(error: unknown) {
  const failure = error as Partial<Failure>;
  note = failure.message ?? "Something went wrong.";
  showStatus();
  if (failure.findings?.length) showFindings(failure.findings);
}

// Sites currently on Tor, as last reported by the backend.
let hosted = new Map<number, { reachable: boolean; broken: boolean; files_confined: boolean }>();
let localUrl = "";
// A message that takes over the status line until the next site switch or publish.
let note = "";

function showStatus() {
  const state = hosted.get(current.id);
  const address = current.address ? `http://${current.address}` : "";
  status.textContent =
    note ||
    (state?.broken
      ? "The onion service stopped working. Publish again to restart it."
      : state && !state.files_confined
        ? `Online at ${address}. This device's system lacks Landlock, so the site's program is confined in every way but one: it is not kept away from this app's other files, all of which are encrypted.`
      : state?.reachable
        ? `Live: ${address}`
        : state
          ? `Online. A new address can take a minute or two to be reachable: ${address}`
          : localUrl
            ? `On this computer only: ${localUrl}`
            : address
              ? `Offline. Address when published: ${address}`
              : "Not published.");
  $("stop").hidden = !state && !localUrl;
}

async function pollTor() {
  const list = await invoke<{ id: number; reachable: boolean; broken: boolean; files_confined: boolean }[]>("onion_status");
  hosted = new Map(list.map((state) => [state.id, state]));
  showStatus();
}

// Nothing is served until a publish button is pressed; edits after it stay
// private until it is pressed again.
$("test").addEventListener("click", async () => {
  note = "";
  try {
    localUrl = await invoke<string>("publish_local", { id: current.id, site });
    showStatus();
  } catch (error) {
    showFailure(error);
  }
});

$<HTMLButtonElement>("publish").addEventListener("click", async (event) => {
  const button = event.currentTarget as HTMLButtonElement;
  const entry = current;
  button.disabled = true;
  note = "Connecting to Tor. The first time can take a minute.";
  showStatus();
  try {
    entry.address = await invoke<string>("publish_onion", { id: entry.id, site: entry.site });
    note = "";
    await pollTor();
  } catch (error) {
    showFailure(error);
  } finally {
    button.disabled = false;
  }
});

$("stop").addEventListener("click", async () => {
  await invoke("stop", { id: current.id });
  localUrl = "";
  note = "";
  await pollTor();
});

// Saving and the vault

let saveTimer = 0;
function scheduleSave() {
  if (!isTauri()) return;
  clearTimeout(saveTimer);
  saveTimer = window.setTimeout(flushSave, 600);
}

// Writes the site being edited now, if an edit is still waiting to be saved.
function flushSave() {
  if (!saveTimer) return;
  clearTimeout(saveTimer);
  saveTimer = 0;
  invoke("save", { id: current.id, site }).catch(showFailure);
}

// Blocks come back from the vault without editor ids.
function withIds(blocks: Block[]) {
  for (const block of blocks) {
    block.id = newId();
    childLists(block).forEach(withIds);
  }
}

async function start() {
  title.value = site.title;
  if (!isTauri()) return refresh();
  const lock = $<HTMLFormElement>("lock");
  const first = $<HTMLInputElement>("passphrase");
  const again = $<HTMLInputElement>("passphrase-again");
  const exists = await invoke<boolean>("vault_exists");
  again.hidden = exists;
  $("lock-text").textContent = exists
    ? "Enter your passphrase to open your sites."
    : "Choose a passphrase. It encrypts your sites and their onion keys on this computer. It cannot be recovered if you forget it.";
  lock.hidden = false;
  first.focus();

  lock.addEventListener("submit", async (event) => {
    event.preventDefault();
    const fail = (message: string) => ($("lock-error").textContent = message);
    if (!exists && first.value.length < 10) return fail("Use at least 10 characters.");
    if (!exists && first.value !== again.value) return fail("The two passphrases do not match.");
    fail("");
    try {
      entries = exists
        ? await invoke<Entry[]>("unlock", { passphrase: first.value })
        : await invoke<Entry[]>("create_vault", { passphrase: first.value, site });
    } catch (error) {
      return fail((error as Failure).message);
    } finally {
      first.value = again.value = "";
    }
    for (const entry of entries) entry.site.pages.forEach((p) => withIds(p.blocks));
    lock.hidden = true;
    open(entries[0]);
    window.setInterval(pollTor, 3000);
  });
}

// Locking forgets the vault's key in the backend. Reloading the page then
// drops every decrypted site from this window's memory as well.
async function lockNow() {
  if (!isTauri()) return;
  flushSave();
  await invoke("lock");
  location.reload();
}
$("lock-now").addEventListener("click", lockNow);

// Left alone for ten minutes, the app locks itself.
const IDLE_MS = 10 * 60 * 1000;
let idle = 0;
function stillHere() {
  clearTimeout(idle);
  idle = window.setTimeout(() => {
    if ($("lock").hidden) void lockNow();
  }, IDLE_MS);
}
for (const kind of ["pointerdown", "keydown", "dragover"]) document.addEventListener(kind, stillHere, true);
stillHere();

// A field edit: keep the inspector as it is so typing keeps focus.
function changed() {
  renderPages();
  void render();
  scheduleSave();
}

function refresh() {
  renderInspector();
  renderSettings();
  renderCollections();
  changed();
}

void start();
