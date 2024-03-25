import * as xpidump from "xpidump";

const updateUI = (xpi) => {
  const $outputPretty = document.getElementById("output-pretty");
  const $outputRaw = document.getElementById("output-raw");

  if (!xpi.has_manifest) {
    $outputPretty.textContent = `⚠️ This file doesn't look like an add-on.`;
    $outputRaw.textContent = "";
    return;
  }

  const { kind, pkcs7_algorithm, manifest, is_staging, is_signed } = xpi;

  // We don't know what kind of add-on we are looking at when it is not signed.
  const prettyKind = is_signed ? `<strong>${kind}</strong> add-on` : "add-on";

  $outputPretty.innerHTML = `
    ✅ ${manifest.id ? `This ${prettyKind} has the following ID in its manifest: <code>${manifest.id}</code>` : `This ${prettyKind} does not have an ID in its manifest`}. Its version is: <code>${manifest.version}</code>.
    <br>
    <br>
    ${is_signed ? `🔐 It has been signed with the <strong>${is_staging ? "staging" : "production"}</strong> root certificate. The PKCS#7 digest algorithm is: <strong>${pkcs7_algorithm}</strong>` : `❌ It doesn't appear to be signed`}.
        `;

  $outputRaw.textContent = JSON.stringify(
    {
      manifest: xpi.manifest,
      signatures: xpi.signatures,
    },
    null,
    2,
  );
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
