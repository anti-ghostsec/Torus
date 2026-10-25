import { invoke, isTauri } from "@tauri-apps/api/core";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";

// Mirrors the model in crates/core. `id` is editor-only; the compiler ignores it.
type Align = "left" | "center" | "right";
type Block = { id: string } & (
  | { type: "heading"; level: number; text: string; align: Align }
  | { type: "text"; text: string; align: Align }
  | { type: "link"; label: string; href: string; align: Align }
  | { type: "divider" }
  | { type: "columns"; columns: Block[][] }
  | { type: "form"; collection: string; submit_label: string; open?: boolean; prefill?: boolean }
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
  | { type: "feed"; collection: string; label: string }
  | { type: "views"; align: Align }
  | { type: "field"; field: string; level: number; align: Align; preview: boolean }
  | { type: "author"; align: Align }
  | { type: "sign_up" | "sign_in" | "sign_out"; submit_label: string }
  | { type: "gate"; audience: "members" | "guests"; blocks: Block[] }
  | { type: "wallet"; label: string }
  | { type: "donate"; label: string }
  | { type: "tip"; amount: string; label: string }
  | { type: "paid"; price: string; label: string; days: number; blocks: Block[] }
);
type BlockType = Block["type"];
type Field = {
  name: string;
  label: string;
  kind: "text" | "long_text" | "formatted" | "code" | "image" | "video";
  required: boolean;
};
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
  // Blocked words, and whether new accounts wait for approval.
  moderation?: {
    blocked_words: string[];
    blocked_held?: boolean;
    approve_accounts?: boolean;
    puzzle_collections?: string[];
    puzzle_sign_up?: boolean;
  };
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
  feed: "Feed for feed readers",
  views: "View count",
  wallet: "Monero: visitor's wallet",
  donate: "Monero: donations",
  tip: "Monero: tip button",
  paid: "Monero: paid content",
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
.paid{min-height:3rem;outline:1px dotted #8888;outline-offset:2px}
.paid.empty::after{content:"Drag blocks here: only those who paid see them";display:block;padding:.75rem;text-align:center;opacity:.6}
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
      return { id, type, collection: someCollection(), submit_label: "Send", open: false, prefill: false };
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
    case "feed":
      return { id, type, collection: someCollection(), label: "Follow in a feed reader" };
    case "views":
      return { id, type, align: "left" };
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
    case "wallet":
      enableAccounts();
      return { id, type, label: "Your Monero" };
    case "donate":
      return { id, type, label: "Support this site" };
    case "tip":
      enableAccounts();
      return { id, type, amount: "0.01", label: "Tip" };
    case "paid":
      enableAccounts();
      return { id, type, price: "0.05", label: "Pay to see this", days: 0, blocks: [] };
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
// The same, where a local name hides it.
const editing = () => current;
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
  if (block.type === "list" || block.type === "gate" || block.type === "paid") return [block.blocks];
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
        field("Then open what was added", flag(!!block.open, (v) => (block.open = v))),
        el("p", "hint", "Afterwards the visitor goes to the new record's own page, if a template page shows that collection. Good for pastes and new articles."),
        field("Start filled in", flag(!!block.prefill, (v) => (block.prefill = v))),
        el("p", "hint", "On a record's page, the form starts with the newest record already added there, so saving makes a changed copy. This is how a wiki edits."),
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
    case "feed":
      inspector.append(
        field("Shows", collectionChoice(block.collection, (v) => (block.collection = v))),
        field("Link words", textInput(block.label, (v) => (block.label = v))),
        el(
          "p",
          "hint",
          "A link to an RSS feed of the newest 30 records, for readers such as Thunderbird or Newsboat. Feed readers also find it on their own. Records carry no time, so neither does the feed. Only collections with a feed block anywhere have a feed.",
        ),
      );
      break;
    case "views":
      inspector.append(
        alignField(block),
        el(
          "p",
          "hint",
          "How often this page has been viewed, said roughly (\"30+ views\"), so nobody can tell when one particular visit happened. Only the number is kept: no addresses, browsers, cookies or times. On a template page, each record has its own count.",
        ),
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
    case "wallet":
      inspector.append(
        field("Heading", textInput(block.label, (v) => (block.label = v))),
        el(
          "p",
          "hint",
          "Shows a signed-in visitor what they hold on this site, their own Monero address to add to it (with a QR code for phone wallets), and a form to withdraw. What they hold can be spent on this site with one click: tips and paid content. Put it on the account page.",
        ),
      );
      break;
    case "donate":
      inspector.append(
        field("Heading", textInput(block.label, (v) => (block.label = v))),
        el("p", "hint", "The site's own Monero address, for anyone to give to, and for signed-in visitors a way to give from what they hold. It goes to what the site has earned."),
      );
      break;
    case "tip":
      inspector.append(
        field("Amount in XMR", textInput(block.amount, (v) => (block.amount = v))),
        field("Button label", textInput(block.label, (v) => (block.label = v))),
        el("p", "hint", "One click gives this much, from what the visitor holds, to whoever added the record shown here (or to the site, where no record is shown). Nothing reaches the chain: it only moves between them."),
      );
      break;
    case "paid": {
      const days = el("input") as HTMLInputElement;
      days.type = "number";
      days.min = "0";
      days.max = "3650";
      days.value = String(block.days);
      days.addEventListener("input", () => {
        block.days = Math.max(0, Math.min(3650, Math.round(Number(days.value) || 0)));
        changed();
      });
      inspector.append(
        field("Price in XMR", textInput(block.price, (v) => (block.price = v))),
        field("Words above the button", textInput(block.label, (v) => (block.label = v))),
        field("Days it lasts (0: once, for good)", days),
        el(
          "p",
          "hint",
          "What you drag inside is shown only to visitors who paid. The payment goes to whoever added the record shown here, or to the site. With days set, it is a pass: a membership of the site, or on someone's profile page, a subscription to them, opening everything they have behind a pass.",
        ),
      );
      break;
    }
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
  const limits = (site.limits ??= { video_mb: 1024, storage_mb: 5120 });
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

  // Moderation: blocked words, and approval of new accounts.
  const mod = (site.moderation ??= { blocked_words: [] });
  const words = el("textarea") as HTMLTextAreaElement;
  words.rows = 3;
  words.placeholder = "one word per line";
  words.value = mod.blocked_words.join("\n");
  words.addEventListener("change", () => {
    mod.blocked_words = words.value.split("\n").map((w) => w.trim()).filter(Boolean);
    words.value = mod.blocked_words.join("\n");
  });
  siteHost.append(field("Blocked words", words));
  siteHost.append(
    field(
      "Hold blocked posts for approval",
      toggle(mod.blocked_held ?? false, (v) => (mod.blocked_held = v)),
    ),
    el("p", "hint", "Off: a post containing a blocked word is refused. On: it is kept out of sight until you approve it. Matching ignores case and looks inside words."),
  );
  if (site.accounts) {
    siteHost.append(
      field("New accounts need approval", toggle(mod.approve_accounts ?? false, (v) => (mod.approve_accounts = v))),
      el("p", "hint", "A new account cannot sign in until you approve it under its collection's “Show what visitors added”."),
      field("Picture puzzle on sign-up", toggle(mod.puzzle_sign_up ?? false, (v) => (mod.puzzle_sign_up = v))),
      el(
        "p",
        "hint",
        "New accounts must type the letters in a picture the site draws. It works without scripts and stops scripts that flood any form they find, but not someone set on reading the pictures by machine. Visitors who cannot see the picture cannot pass it. Collections can ask for one too, in their settings.",
      ),
    );
  }

  // Auto-lock applies to the whole app, not one site, and is saved at once.
  const lockAfter = el("input") as HTMLInputElement;
  lockAfter.type = "number";
  lockAfter.min = "0";
  lockAfter.max = "1440";
  void invoke<number>("auto_lock_minutes").then((m) => (lockAfter.value = String(m)));
  lockAfter.addEventListener("change", async () => {
    const minutes = Math.max(0, Math.min(1440, Math.round(Number(lockAfter.value) || 0)));
    lockAfter.value = String(minutes);
    idleMinutes = minutes;
    stillHere();
    try {
      await invoke("set_auto_lock_minutes", { minutes });
    } catch (error) {
      showFailure(error);
    }
  });
  siteHost.append(
    field("Lock after idle minutes (0 = never)", lockAfter),
    el("p", "hint", "Applies to the whole app. Panic (the toolbar button, or Ctrl+Shift+Backspace) takes every site offline, locks, and closes at once."),
  );

  // A backup of the whole installation: the vault and every site's data, all
  // already encrypted. Exporting takes every site offline first.
  const backup = el("button", "", "Back up everything to a file");
  backup.addEventListener("click", async () => {
    const stamp = new Date().toISOString().slice(0, 10);
    const file = await saveDialog({ defaultPath: `torus-backup-${stamp}.torusbak`, filters: [{ name: "Torus backup", extensions: ["torusbak"] }] });
    if (!file) return;
    backup.disabled = true;
    backup.textContent = "Backing up… (sites are offline)";
    try {
      await invoke("export_backup", { file });
      note = "Backup saved. Keep it somewhere safe: it opens only with this vault's passphrase.";
      showStatus();
    } catch (error) {
      showFailure(error);
    } finally {
      backup.disabled = false;
      backup.textContent = "Back up everything to a file";
    }
  });
  siteHost.append(
    field("Backup", backup),
    el("p", "hint", "One file with the vault and every site's data, all encrypted. It opens only with this vault's passphrase. Restore it on a fresh install from the Unlock screen."),
  );

  // One site at a time, to another installation or to keep apart, sealed
  // under a passphrase chosen for the file.
  const filePass = el("input") as HTMLInputElement;
  filePass.type = "password";
  filePass.autocomplete = "off";
  filePass.placeholder = "at least 10 characters";
  const withContent = flag(false, () => {});
  const withAddress = flag(false, () => {});
  const exportSite = el("button", "", "Export this site");
  exportSite.addEventListener("click", async () => {
    if (filePass.value.length < 10) return showFailure({ message: "Choose a passphrase of at least 10 characters for the file." } as Failure);
    const name = slug(site.title) || "site";
    const file = await saveDialog({ defaultPath: `${name}.torussite`, filters: [{ name: "Torus site", extensions: ["torussite"] }] });
    if (!file) return;
    flushSave();
    exportSite.disabled = true;
    try {
      await invoke("export_site", {
        id: openEntry().id,
        file,
        passphrase: filePass.value,
        content: withContent.checked,
        address: withAddress.checked,
      });
      filePass.value = "";
      if (withContent.checked) localUrl = "";
      note = withAddress.checked
        ? "Site exported, with its address. Do not run it in two places at once: the two copies would fight over the address."
        : "Site exported.";
      showStatus();
      await pollTor();
    } catch (error) {
      showFailure(error);
    } finally {
      exportSite.disabled = false;
    }
  });
  const importSite = el("button", "", "Import a site from a file");
  importSite.addEventListener("click", async () => {
    const file = await openDialog({ filters: [{ name: "Torus site", extensions: ["torussite"] }] });
    if (!file || Array.isArray(file)) return;
    if (!filePass.value) return showFailure({ message: "Type the file's passphrase first, then import." } as Failure);
    importSite.disabled = true;
    importSite.textContent = "Importing…";
    try {
      const entry = await invoke<Entry>("import_site", { file, passphrase: filePass.value });
      filePass.value = "";
      entry.site.pages.forEach((p) => withIds(p.blocks));
      entries.push(entry);
      open(entry);
      note = "Site imported as a new site.";
      showStatus();
    } catch (error) {
      showFailure(error);
    } finally {
      importSite.disabled = false;
      importSite.textContent = "Import a site from a file";
    }
  });
  siteHost.append(
    field("Site file passphrase", filePass),
    field("Include what visitors added", withContent),
    field("Include the onion address", withAddress),
    exportSite,
    importSite,
    el(
      "p",
      "hint",
      "Exports just this site to a .torussite file, sealed with the passphrase above. Its design always goes; what visitors added (accounts, posts, files) and its .onion address only if ticked. Including what visitors added takes the site offline while it is copied. Importing adds the file's site here as a new site.",
    ),
  );

  // Decoy passphrase: a second passphrase that opens a separate, empty
  // installation. Only offered from the real compartment.
  void invoke<boolean>("in_decoy").then((decoy) => {
    if (decoy) return;
    const decoyInput = el("input") as HTMLInputElement;
    decoyInput.type = "password";
    decoyInput.autocomplete = "off";
    decoyInput.placeholder = "leave blank to turn off";
    const setDecoy = el("button", "", "Set decoy passphrase");
    setDecoy.addEventListener("click", async () => {
      setDecoy.disabled = true;
      try {
        await invoke("set_decoy", { passphrase: decoyInput.value });
        decoyInput.value = "";
        note = "Decoy passphrase saved. Entering it on the Unlock screen opens a separate, empty set of sites.";
        showStatus();
      } catch (error) {
        showFailure(error);
      } finally {
        setDecoy.disabled = false;
      }
    });
    siteHost.append(
      field("Decoy passphrase", decoyInput),
      setDecoy,
      el(
        "p",
        "hint",
        "A second passphrase that opens a separate, empty installation instead of your real one. It must differ from your real passphrase. Nobody can tell from the files whether you have set one. Setting or changing it takes every site offline for a moment.",
      ),
    );
  });

  // Replaces every page and collection, so it also takes two clicks.
  const kinds: [string, string][] = [
    ["video", "Video site"],
    ["board", "Anonymous board"],
    ["microblog", "Microblog"],
    ["wiki", "Wiki"],
    ["pastebin", "Pastebin"],
  ];
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

  siteHost.append(addressMiner());
  siteHost.append(walletBox());

  // Deleting a site destroys its onion key, so it takes two deliberate clicks.
  const erase = el("button", "", "Delete site");
  erase.disabled = entries.length < 2;
  erase.addEventListener("click", async () => {
    if (erase.dataset.armed) return void deleteCurrent();
    erase.dataset.armed = "1";
    const held = await invoke<number>("wallet_held_by", { id: editing().id }).catch(() => 0);
    erase.textContent = held
      ? `Click again: erases the site and its address forever. The ${xmr(held)} it and its users hold becomes yours`
      : "Click again: erases the site and its address forever";
  });
  siteHost.append(erase);
}

// Monero

type WalletSummary = {
  address: string;
  node: string;
  chosen: boolean;
  own: number;
  spendable: number;
  arriving: number;
  owed: number;
  height: number;
  tip: number | null;
  trouble: string | null;
  sites: { site: number; address: string; earned: number; users: number; held_by_users: number; daily_limit: number }[];
};
type RestoreKeys = { address: string; spend_key: string; view_key: string; height: number };

const PER_XMR = 1_000_000_000_000;
// Whole piconero, printed without rounding.
function xmr(amount: number) {
  const whole = Math.floor(amount / PER_XMR);
  const part = String(amount % PER_XMR).padStart(12, "0").replace(/0+$/, "");
  return part ? `${whole}.${part} XMR` : `${whole} XMR`;
}

let walletTimer = 0;

function walletBox() {
  const box = el("div", "wallet");
  box.append(el("h3", "", "Monero"));
  const body = el("div");
  box.append(body);
  const plain = (text: string) => el("p", "hint", text);
  const input = (placeholder: string, secret = false) => {
    const node = el("input") as HTMLInputElement;
    node.placeholder = placeholder;
    node.autocomplete = "off";
    node.spellcheck = false;
    if (secret) node.type = "password";
    return node;
  };
  const show = async () => {
    clearTimeout(walletTimer);
    let summary: WalletSummary | null = null;
    try {
      summary = await invoke<WalletSummary | null>("wallet");
    } catch {
      return;
    }
    if (!box.isConnected) return;
    body.replaceChildren();
    // Every vault has one, made with it; only while locked is there none.
    if (!summary) return;
    // The node.
    const node = input("chosen for you: leave empty");
    node.value = summary.chosen ? summary.node : "";
    const setNode = el("button", "", "Use this node");
    setNode.addEventListener("click", async () => {
      try {
        await invoke("wallet_node", { node: node.value });
        note = node.value.trim() ? "Reaching that node through Tor." : "Back to a node chosen for you.";
        showStatus();
        void show();
      } catch (error) {
        showFailure(error);
      }
    });
    const state = summary.trouble
      ? `The node did not answer (${summary.trouble}). Trying ${summary.chosen ? "it" : "another"} again shortly.`
      : summary.tip === null
        ? "Nothing to do yet: the wallet goes online once a site's visitors use it."
        : summary.height < summary.tip
          ? `Reading the chain: block ${summary.height} of ${summary.tip}.`
          : `Up to date at block ${summary.tip}.`;
    body.append(
      plain(
        "Every site's Monero blocks use this wallet by themselves: each visitor gets an address of their own, and whatever a site earns is yours at once.",
      ),
      plain(state),
      plain(`Node: ${summary.node}${summary.chosen ? "" : ", chosen for you from Monero nodes that are reached only through Tor. A node of your own is more private still."}`),
      field("Your own node (optional)", node),
      setNode,
    );

    // The owner's own account.
    body.append(
      el("p", "balance", `Yours: ${xmr(summary.own)}`),
      plain(`The wallet holds ${xmr(summary.spendable)} that can be spent now${summary.arriving ? ` and ${xmr(summary.arriving)} still settling` : ""}; ${xmr(summary.owed)} of it is owed to you, your sites and their users.`),
      field("Your own address", Object.assign(input(""), { value: summary.address, readOnly: true })),
    );
    const to = input("a Monero address");
    const amount = input("XMR, or nothing for all of it");
    const send = el("button", "", "Send");
    send.addEventListener("click", async () => {
      if (!send.dataset.armed) {
        send.dataset.armed = "1";
        send.textContent = `Click again: send ${amount.value.trim() ? `${amount.value.trim()} XMR` : "all of yours"} out of the wallet`;
        return;
      }
      send.disabled = true;
      try {
        const [sent, fee] = await invoke<[number, number]>("wallet_send", { address: to.value, amount: amount.value || null });
        note = `Sent ${xmr(sent)}, and ${xmr(fee)} to the network as its fee.`;
        showStatus();
        void show();
      } catch (error) {
        showFailure(error);
        send.disabled = false;
      }
    });
    body.append(el("h4", "", "Send from yours"), field("To", to), field("Amount", amount), send);

    // This site's books.
    const mine = summary.sites.find((s) => s.site === current.id);
    body.append(el("h4", "", "This site"));
    if (!mine) {
      body.append(plain("Nothing yet: the site's books open when a visitor first uses a Monero block."));
    } else {
      const limit = input("XMR per day");
      limit.value = xmr(mine.daily_limit).replace(" XMR", "");
      const setLimit = el("button", "", "Set limit");
      setLimit.addEventListener("click", async () => {
        try {
          await invoke("wallet_limit", { id: current.id, amount: limit.value });
          note = "Limit set.";
          showStatus();
        } catch (error) {
          showFailure(error);
        }
      });
      body.append(
        plain(
          `Earned in all: ${xmr(mine.earned)}, already yours. ${mine.users} visitors hold ${xmr(mine.held_by_users)}, kept apart from yours; an account deleted with some still in it leaves it to you.`,
        ),
        field("Withdrawals by this site's visitors, together, per day", limit),
        setLimit,
        plain(
          "The site's host process faces the network. Were it ever taken over, this limit is the most it could take out of the wallet in a day, and only from what this site's visitors hold: never from yours.",
        ),
        plain(`Donations go to the site's own address: ${mine.address}`),
      );
    }

    // Restoring elsewhere.
    const pass = input("this vault's passphrase", true);
    const reveal = el("button", "", "Show the wallet's keys");
    const keys = el("div");
    reveal.addEventListener("click", async () => {
      try {
        const k = await invoke<RestoreKeys>("wallet_keys", { passphrase: pass.value });
        pass.value = "";
        keys.replaceChildren(
          plain("Whoever sees these has the coins. Write them down on paper; never put them in a file, a photo or a message."),
          field("Address", Object.assign(input(""), { value: k.address, readOnly: true })),
          field("Secret spend key", Object.assign(input(""), { value: k.spend_key, readOnly: true })),
          field("Secret view key", Object.assign(input(""), { value: k.view_key, readOnly: true })),
          plain(`Restore height: ${k.height}. Any Monero wallet (Feather, Cake, the official one) can be restored from these: choose to restore from keys.`),
        );
        setTimeout(() => keys.replaceChildren(), 120_000);
      } catch (error) {
        showFailure(error);
      }
    });
    body.append(el("h4", "", "Back up"), plain("The vault's backup has the wallet in it. To move the coins elsewhere without Torus, restore the wallet from its keys."), field("Passphrase", pass), reveal, keys);
    walletTimer = window.setTimeout(() => void show(), 20_000);
  };
  void show();
  return box;
}

// Choosing an address

type MineStatus = {
  site: number;
  prefix: string;
  tried: number;
  per_second: number;
  expected: number;
  threads: number;
  found: string | null;
};

// One poll for the whole window, however often the panel is redrawn.
let minePoll: number | null = null;
let mineView: ((status: MineStatus | null) => void) | null = null;

function duration(seconds: number) {
  if (!Number.isFinite(seconds)) return "a while";
  if (seconds < 90) return `${Math.max(1, Math.round(seconds))} seconds`;
  if (seconds < 90 * 60) return `${Math.round(seconds / 60)} minutes`;
  if (seconds < 48 * 3600) return `${Math.round(seconds / 3600)} hours`;
  if (seconds < 60 * 86400) return `${Math.round(seconds / 86400)} days`;
  return `${Math.round(seconds / (365 * 86400))} years`;
}

function pollMining() {
  if (minePoll !== null) return;
  minePoll = window.setInterval(async () => {
    const status = await invoke<MineStatus | null>("mine_status");
    mineView?.(status);
    if (!status || status.found) {
      window.clearInterval(minePoll!);
      minePoll = null;
    }
  }, 1000);
}

// An address that begins with chosen letters, found by trying keys until
// one matches. Each extra letter takes 32 times as long.
function addressMiner() {
  const box = el("div", "miner");
  const wanted = el("input");
  wanted.placeholder = "e.g. torus, anonsite, anonpost";
  wanted.spellcheck = false;
  const estimate = el("p", "hint");
  const progress = el("p", "hint");
  const start = el("button", "", "Find this address");
  const use = el("button", "", "Use this address");
  const keep = el("button", "", "Save it for later");
  use.hidden = keep.hidden = true;
  // A first guess before any search has run: a little over a million keys a second per processor.
  const typical = 1_500_000 * Math.max(1, (navigator.hardwareConcurrency || 2) - 1);
  const words = () =>
    wanted.value
      .toLowerCase()
      .split(/[\s,]+/)
      .filter(Boolean);
  const explain = () => {
    const list = words();
    if (list.length === 0) {
      return void (estimate.textContent =
        "Letters a to z and digits 2 to 7. Each letter makes it about 32 times longer to find. List several, separated by commas, and the first one found is kept.");
    }
    const bad = list.find((w) => /[^a-z2-7]/.test(w));
    if (bad) return void (estimate.textContent = `"${bad}": only a to z and 2 to 7 can appear in an onion address (no 0, 1, 8 or 9).`);
    const tries = 1 / list.reduce((sum, w) => sum + Math.pow(32, -w.length), 0);
    const which = list.length > 1 ? `one of these ${list.length}` : `"${list[0]}"`;
    estimate.textContent = `On this device, ${which} takes about ${duration(tries / typical)} to find, on average. It could be sooner or later.`;
  };
  wanted.addEventListener("input", explain);
  explain();

  mineView = (status) => {
    const mine = status && status.site === current.id ? status : null;
    if (!mine) {
      start.textContent = "Find this address";
      progress.textContent = status ? "Another site's address is being searched for." : "";
      use.hidden = keep.hidden = true;
      return;
    }
    if (mine.found) {
      start.textContent = "Search again";
      progress.textContent = `Found: ${mine.found}`;
      use.hidden = keep.hidden = false;
      return;
    }
    start.textContent = "Stop";
    const chance = 1 - Math.exp(-mine.tried / mine.expected);
    const left = Math.max(0, mine.expected - mine.tried) / Math.max(1, mine.per_second);
    progress.textContent =
      `Searching for ${mine.prefix} on ${mine.threads} processors: ${(mine.per_second / 1e6).toFixed(1)} million keys a second, ` +
      `${(mine.tried / 1e6).toFixed(0)} million tried. ${Math.round(chance * 100)}% of searches this long have found it; about ${duration(left)} to go on average. ` +
      "It keeps going while the app is open, even locked. Closing the app stops it.";
  };

  start.addEventListener("click", async () => {
    try {
      if (start.textContent === "Stop") {
        await invoke("mine_stop");
        mineView?.(null);
        return;
      }
      const status = await invoke<MineStatus>("mine_start", { id: current.id, prefix: wanted.value });
      mineView?.(status);
      pollMining();
    } catch (error) {
      showFailure(error);
    }
  });

  // Giving a site another address: the old one is kept among the saved ones.
  const replaced = (button: HTMLButtonElement, label: string) => {
    if (current.address && !button.dataset.armed) {
      button.dataset.armed = "1";
      button.textContent = `Click again: replaces ${current.address} (it is kept under Saved addresses)`;
      return false;
    }
    delete button.dataset.armed;
    button.textContent = label;
    return true;
  };

  use.addEventListener("click", async () => {
    if (!replaced(use, "Use this address")) return;
    try {
      current.address = await invoke<string>("mine_use", { id: current.id, replace: Boolean(current.address) });
      use.hidden = keep.hidden = true;
      progress.textContent = `This site's address is now ${current.address}. Publish it to Tor to put it online there.`;
      showStatus();
      void listSaved();
    } catch (error) {
      showFailure(error);
    }
  });

  keep.addEventListener("click", async () => {
    try {
      const address = await invoke<string>("mine_save");
      use.hidden = keep.hidden = true;
      progress.textContent = `Saved ${address}. It is kept in the vault until you use or forget it.`;
      void listSaved();
    } catch (error) {
      showFailure(error);
    }
  });

  // Saved addresses: kept in the vault, for any site, or to move elsewhere.
  const saved = el("div", "saved");
  const filePass = el("input") as HTMLInputElement;
  filePass.type = "password";
  filePass.autocomplete = "off";
  filePass.placeholder = "at least 10 characters";
  const needPass = () => {
    if (filePass.value.length >= 10) return true;
    showFailure({ message: "Type a passphrase of at least 10 characters for the address file first." } as Failure);
    return false;
  };
  const exportAddress = async (address: string) => {
    if (!needPass()) return;
    const file = await saveDialog({
      defaultPath: `${address.slice(0, 16)}.toruskey`,
      filters: [{ name: "Torus address", extensions: ["toruskey"] }],
    });
    if (!file) return;
    try {
      await invoke("export_key", { address, file, passphrase: filePass.value });
      filePass.value = "";
      note = "Address file saved. Anyone with it and its passphrase can run a site at that address.";
      showStatus();
    } catch (error) {
      showFailure(error);
    }
  };
  async function listSaved() {
    let addresses: string[] = [];
    try {
      addresses = await invoke<string[]>("saved_addresses");
    } catch {
      return;
    }
    saved.replaceChildren();
    if (current.address) {
      const row = el("div", "record");
      const out = el("button", "", "Export");
      out.addEventListener("click", () => void exportAddress(current.address!));
      row.append(el("span", "", `This site: ${current.address}`), out);
      saved.append(row);
    }
    if (addresses.length === 0) saved.append(el("p", "hint", "No saved addresses."));
    for (const address of addresses) {
      const row = el("div", "record");
      const take = el("button", "", "Use for this site");
      take.addEventListener("click", async () => {
        if (!replaced(take, "Use for this site")) return;
        try {
          current.address = await invoke<string>("use_saved", { id: current.id, address, replace: Boolean(current.address) });
          showStatus();
          void listSaved();
        } catch (error) {
          showFailure(error);
        }
      });
      const out = el("button", "", "Export");
      out.addEventListener("click", () => void exportAddress(address));
      const forget = el("button", "", "Forget");
      forget.addEventListener("click", async () => {
        if (!forget.dataset.armed) {
          forget.dataset.armed = "1";
          forget.textContent = "Click again: gone for good";
          return;
        }
        await invoke("forget_saved", { address }).catch(showFailure);
        void listSaved();
      });
      row.append(el("span", "", address), take, out, forget);
      saved.append(row);
    }
  }
  const bring = el("button", "", "Import an address file");
  bring.addEventListener("click", async () => {
    if (!filePass.value) return showFailure({ message: "Type the file's passphrase first, then import." } as Failure);
    const file = await openDialog({ filters: [{ name: "Torus address", extensions: ["toruskey"] }] });
    if (!file || Array.isArray(file)) return;
    try {
      const address = await invoke<string>("import_key", { file, passphrase: filePass.value });
      filePass.value = "";
      note = `Imported ${address}. It is under Saved addresses.`;
      showStatus();
      void listSaved();
    } catch (error) {
      showFailure(error);
    }
  });

  box.append(
    field("Choose the address's first letters", wanted),
    estimate,
    start,
    use,
    keep,
    progress,
    el("h3", "", "Saved addresses"),
    saved,
    field("Address file passphrase", filePass),
    bring,
    el(
      "p",
      "hint",
      "An address file holds an address's secret key, sealed with the passphrase above. Whoever has the file and the passphrase can run a site at that address, and so can whoever made it: never use an address someone else found for you.",
    ),
  );
  void listSaved();
  void invoke<MineStatus | null>("mine_status").then((status) => {
    mineView?.(status);
    if (status && !status.found) pollMining();
  });
  return box;
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
    const named = block.type === "form" || block.type === "list" || block.type === "count" || block.type === "feed";
    if (named && block.collection === old) block.collection = name;
  });
  const mod = site.moderation;
  if (mod?.puzzle_collections) mod.puzzle_collections = mod.puzzle_collections.map((n) => (n === old ? name : n));
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
        field(
          "Picture puzzle before adding",
          flag((site.moderation?.puzzle_collections ?? []).includes(collection.name), (v) => {
            const mod = (site.moderation ??= { blocked_words: [] });
            const others = (mod.puzzle_collections ?? []).filter((n) => n !== collection.name);
            mod.puzzle_collections = v ? [...others, collection.name] : others;
          }),
        ),
      );
    }

    for (const item of collection.fields) {
      const row = el("div", "field-row");
      const label = textInput(item.label, (v) => (item.label = v));
      label.title = "What visitors see next to this input";
      const kinds: [Field["kind"], string][] = [
        ["text", "Short"],
        ["long_text", "Long"],
        ["formatted", "Formatted"],
        ["code", "Code"],
        ["image", "Picture"],
        ["video", "Video"],
      ];
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
            .filter((f) => f.kind !== "image" && f.kind !== "video")
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

// The site being edited, for code where `current` names something else.
const openEntry = () => current;

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
  const decoy = $<HTMLInputElement>("decoy-passphrase");
  const exists = await invoke<boolean>("vault_exists");
  again.hidden = exists;
  decoy.hidden = $("decoy-hint").hidden = exists;
  $("lock-text").textContent = exists
    ? "Enter your passphrase to open your sites."
    : "Choose a passphrase. It encrypts your sites and their onion keys on this computer. It cannot be recovered if you forget it.";
  lock.hidden = false;
  first.focus();

  // On a fresh install, offer to restore a backup instead of starting over.
  const restore = $<HTMLButtonElement>("restore");
  restore.hidden = exists;
  restore.addEventListener("click", async () => {
    const file = await openDialog({ filters: [{ name: "Torus backup", extensions: ["torusbak"] }] });
    if (!file || Array.isArray(file)) return;
    restore.disabled = true;
    restore.textContent = "Restoring…";
    try {
      await invoke("import_backup", { file });
      location.reload();
    } catch (error) {
      $("lock-error").textContent = (error as Failure).message;
      restore.disabled = false;
      restore.textContent = "Restore from a backup";
    }
  });

  lock.addEventListener("submit", async (event) => {
    event.preventDefault();
    const fail = (message: string) => ($("lock-error").textContent = message);
    if (!exists && first.value.length < 10) return fail("Use at least 10 characters.");
    if (!exists && first.value !== again.value) return fail("The two passphrases do not match.");
    if (!exists && decoy.value && decoy.value.length < 10) return fail("Use at least 10 characters for the decoy passphrase too.");
    if (!exists && decoy.value && decoy.value === first.value) return fail("The decoy passphrase must differ from your real one.");
    fail("");
    try {
      entries = exists
        ? await invoke<Entry[]>("unlock", { passphrase: first.value })
        : await invoke<Entry[]>("create_vault", { passphrase: first.value, site });
      // The vault exists and is open now; a decoy can only be set from here.
      if (!exists && decoy.value) await invoke("set_decoy", { passphrase: decoy.value });
    } catch (error) {
      return fail((error as Failure).message);
    } finally {
      first.value = again.value = decoy.value = "";
    }
    for (const entry of entries) entry.site.pages.forEach((p) => withIds(p.blocks));
    lock.hidden = true;
    idleMinutes = await invoke<number>("auto_lock_minutes");
    stillHere();
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

// Panic: take every site offline, forget the key, and close the app, in one
// step. The backend does the work, then exits; nothing is left running.
async function panic() {
  if (!isTauri()) return;
  flushSave();
  try {
    await invoke("panic");
  } catch {
    // Exiting mid-call ends this side too; nothing more to do.
  }
}
$("panic").addEventListener("click", panic);
// A hotkey unlikely to be pressed by accident, while the window has focus.
document.addEventListener("keydown", (event) => {
  if (event.ctrlKey && event.shiftKey && event.key === "Backspace") {
    event.preventDefault();
    void panic();
  }
});

// Left alone, the app locks itself. How long is the owner's choice, kept in
// the vault; 0 means never. Ten minutes until they set it otherwise.
let idleMinutes = 10;
let idle = 0;
function stillHere() {
  clearTimeout(idle);
  if (idleMinutes <= 0) return;
  idle = window.setTimeout(
    () => {
      if ($("lock").hidden) void lockNow();
    },
    idleMinutes * 60 * 1000,
  );
}
for (const kind of ["pointerdown", "keydown", "dragover"]) document.addEventListener(kind, stillHere, true);

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
