function A({ html }) {
  // ruleid: web-9-react-dangerously-set-inner-html
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
function B({ html }) {
  // ok: web-9-react-dangerously-set-inner-html
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}
