import * as xpidump from "xpidump";

const updateUI = (xpi) => {
  const $outputPretty = document.getElementById("output-pretty");
  const $outputRaw = document.getElementById("output-raw");

  if (!xpi.has_manifest) {
    $outputPretty.textContent = `⚠️ This file doesn't look like an add-on.`;
    $outputRaw.textContent = "";
    return;
  }

  const {
    cose_algorithm,
    has_cose_sig,
    has_pkcs7_sig,
    env,
    kind,
    manifest,
    pkcs7_algorithm,
  } = xpi;

  // We don't know what kind of add-on we are looking at when it is not signed.
  const prettyKind = has_pkcs7_sig
    ? `<strong>${kind}</strong> add-on`
    : "add-on";

  $outputPretty.innerHTML = `
    ✅ ${manifest.id ? `This ${prettyKind} has the following ID in its manifest: <code>${manifest.id}</code>` : `This ${prettyKind} does not have an ID in its manifest`}. Its version is: <code>${manifest.version}</code>.
    <br>
    <br>
    ${has_pkcs7_sig ? `${has_cose_sig ? "🔐" : "🔓"} It has been signed with the <strong>${env}</strong> root certificate. ${has_cose_sig ? "This add-on is dual-signed (PKCS#7 and COSE)" : "This add-on is <strong>not</strong> signed with COSE"}. The PKCS#7 digest algorithm is: <strong>${pkcs7_algorithm}</strong>. ${has_cose_sig ? `The COSE algorithm is: <strong>${cose_algorithm}</strong>.` : ""}` : `❌ It doesn't appear to be signed.`}
        `;

  $outputRaw.textContent = JSON.stringify(xpi.to_js(), null, 2);
};

document.getElementById("input-file").addEventListener(
  "change",
  (event) => {
    // TODO: make sure `target` is defined
    const { files } = event.target;
    const reader = new FileReader();
    reader.onload = function (e) {
      const xpi = new xpidump.XPI(new Uint8Array(reader.result));

      updateUI(xpi);
    };
    // TODO: check the presence of a file
    reader.readAsArrayBuffer(files[0]);
  },
  false,
);
