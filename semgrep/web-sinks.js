// ruleid: web-9-html-sink-assignment
el.innerHTML = userInput;
// ok: web-9-html-sink-assignment
el.innerHTML = "<b>static</b>";
// ok: web-9-html-sink-assignment
el.innerHTML = DOMPurify.sanitize(userInput);
// ruleid: web-9-html-sink-assignment
el.insertAdjacentHTML("beforeend", html);
// ok: web-9-html-sink-assignment
el.insertAdjacentHTML("beforeend", DOMPurify.sanitize(html));
// ruleid: web-9-html-sink-assignment
document.write(x);
// ruleid: web-9-html-sink-assignment
frame.srcdoc = page;
// ok: web-9-html-sink-assignment
el.textContent = userInput;

// ruleid: web-10-dynamic-url-sink
a.href = params.get("next");
// ruleid: web-10-dynamic-url-sink
frame.src = params.get("u");
// ruleid: web-10-dynamic-url-sink
document.querySelector("iframe").src = params.get("u");
// ruleid: web-10-dynamic-url-sink
a.href = URL.createObjectURL(blob);
// ok: web-10-dynamic-url-sink
a.href = "/home";
// ok: web-10-dynamic-url-sink
a.href = urls.safeUrl(params.get("next"));
// ruleid: web-10-dynamic-url-sink
location.assign(target);
// ok: web-10-dynamic-url-sink
location.assign(urls.safeUrl(target));
// ruleid: web-10-dynamic-url-sink
a.setAttribute("href", target);
// ok: web-10-dynamic-url-sink
a.setAttribute("href", "/static");
// ruleid: web-10-dynamic-url-sink
window.open(link, "_blank");
// ok: web-10-dynamic-url-sink
window.open("/help", "_blank");

// ruleid: web-10-javascript-url-literal
const bad = "javascript:alert(1)";
// ok: web-10-dynamic-url-sink
location.replace("/login");
// ruleid: web-10-dynamic-url-sink
window.location.assign(next);
// ruleid: web-10-dynamic-url-sink
window.location.replace(next);
// ruleid: web-10-dynamic-url-sink
document.location = next;
// ok: web-10-dynamic-url-sink
window.location.replace("/done");
// ruleid: web-10-dynamic-url-sink
btn.setAttribute("formaction", next);
// ruleid: web-9-html-sink-assignment
frame.setAttribute("srcdoc", page);
// ok: web-9-html-sink-assignment
frame.setAttribute("srcdoc", "<p>static</p>");

function loadScript(u) {
  const s = document.createElement("script");
  // ruleid: web-10-dynamic-url-sink
  s.src = u;
  const f = document.createElement("iframe");
  // ruleid: web-10-dynamic-url-sink
  f.setAttribute("src", u);
  const im = document.createElement("img");
  // ok: web-10-dynamic-url-sink
  im.src = u;
  const pic = new Image();
  // ok: web-10-dynamic-url-sink
  pic.src = u;
  const o = document.createElement("object");
  // ruleid: web-10-dynamic-url-sink
  o.data = u;
  const v = document.createElement("video");
  // ok: web-10-dynamic-url-sink
  v.setAttribute("src", u);
}
async function viaBlob(p) {
  const fr = document.createElement("iframe");
  // ruleid: web-10-dynamic-url-sink
  fr.src = URL.createObjectURL(await (await fetch(p.get("u"))).blob());
}
