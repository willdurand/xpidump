"use strict";(self.webpackChunkxpidump_webapp=self.webpackChunkxpidump_webapp||[]).push([[237],{941:(t,n,e)=>{e.a(t,(async(t,r)=>{try{e.d(n,{OM:()=>o.OM});var i=e(471),o=e(87),s=t([i]);i=(s.then?(await s)():s)[0],(0,o.lI)(i),r()}catch(t){r(t)}}))},87:(t,n,e)=>{let r;function i(t){r=t}e.d(n,{BZ:()=>$,DK:()=>O,M2:()=>T,OM:()=>x,QU:()=>E,Qn:()=>S,bk:()=>k,lI:()=>i,ot:()=>I,rl:()=>C,yc:()=>v}),t=e.hmd(t);const o=new Array(128).fill(void 0);function s(t){return o[t]}o.push(void 0,null,!0,!1);let _=o.length;function c(t){const n=s(t);return function(t){t<132||(o[t]=_,_=t)}(t),n}function a(t){_===o.length&&o.push(o.length+1);const n=_;return _=o[n],o[n]=t,n}let g=new("undefined"==typeof TextDecoder?(0,t.require)("util").TextDecoder:TextDecoder)("utf-8",{ignoreBOM:!0,fatal:!0});g.decode();let d=null;function u(){return null!==d&&0!==d.byteLength||(d=new Uint8Array(r.memory.buffer)),d}function l(t,n){return t>>>=0,g.decode(u().subarray(t,t+n))}function f(t){const n=typeof t;if("number"==n||"boolean"==n||null==t)return`${t}`;if("string"==n)return`"${t}"`;if("symbol"==n){const n=t.description;return null==n?"Symbol":`Symbol(${n})`}if("function"==n){const n=t.name;return"string"==typeof n&&n.length>0?`Function(${n})`:"Function"}if(Array.isArray(t)){const n=t.length;let e="[";n>0&&(e+=f(t[0]));for(let r=1;r<n;r++)e+=", "+f(t[r]);return e+="]",e}const e=/\[object ([^\]]+)\]/.exec(toString.call(t));let r;if(!(e.length>1))return toString.call(t);if(r=e[1],"Object"==r)try{return"Object("+JSON.stringify(t)+")"}catch(t){return"Object"}return t instanceof Error?`${t.name}: ${t.message}\n${t.stack}`:r}let b=0,h=new("undefined"==typeof TextEncoder?(0,t.require)("util").TextEncoder:TextEncoder)("utf-8");const p="function"==typeof h.encodeInto?function(t,n){return h.encodeInto(t,n)}:function(t,n){const e=h.encode(t);return n.set(e),{read:t.length,written:e.length}};let w=null;function y(){return null!==w&&0!==w.byteLength||(w=new Int32Array(r.memory.buffer)),w}const m="undefined"==typeof FinalizationRegistry?{register:()=>{},unregister:()=>{}}:new FinalizationRegistry((t=>r.__wbg_xpi_free(t>>>0)));class x{__destroy_into_raw(){const t=this.__wbg_ptr;return this.__wbg_ptr=0,m.unregister(this),t}free(){const t=this.__destroy_into_raw();r.__wbg_xpi_free(t)}constructor(t){const n=function(t,n){const e=n(1*t.length,1)>>>0;return u().set(t,e/1),b=t.length,e}(t,r.__wbindgen_malloc),e=b,i=r.xpi_new(n,e);return this.__wbg_ptr=i>>>0,this}get manifest(){return c(r.xpi_manifest(this.__wbg_ptr))}get signatures(){return c(r.xpi_signatures(this.__wbg_ptr))}get has_manifest(){return 0!==r.xpi_has_manifest(this.__wbg_ptr)}get is_pkcs7_signed(){return 0!==r.xpi_is_pkcs7_signed(this.__wbg_ptr)}get is_staging(){return 0!==r.xpi_is_staging(this.__wbg_ptr)}get pkcs7_algorithm(){let t,n;try{const o=r.__wbindgen_add_to_stack_pointer(-16);r.xpi_pkcs7_algorithm(o,this.__wbg_ptr);var e=y()[o/4+0],i=y()[o/4+1];return t=e,n=i,l(e,i)}finally{r.__wbindgen_add_to_stack_pointer(16),r.__wbindgen_free(t,n,1)}}get kind(){let t,n;try{const o=r.__wbindgen_add_to_stack_pointer(-16);r.xpi_kind(o,this.__wbg_ptr);var e=y()[o/4+0],i=y()[o/4+1];return t=e,n=i,l(e,i)}finally{r.__wbindgen_add_to_stack_pointer(16),r.__wbindgen_free(t,n,1)}}get is_cose_signed(){return 0!==r.xpi_is_cose_signed(this.__wbg_ptr)}get cose_algorithm(){let t,n;try{const o=r.__wbindgen_add_to_stack_pointer(-16);r.xpi_cose_algorithm(o,this.__wbg_ptr);var e=y()[o/4+0],i=y()[o/4+1];return t=e,n=i,l(e,i)}finally{r.__wbindgen_add_to_stack_pointer(16),r.__wbindgen_free(t,n,1)}}}function k(t){c(t)}function $(t){return a(s(t))}function v(t,n){return a(l(t,n))}function O(t,n,e){s(t)[c(n)]=c(e)}function T(){return a(new Array)}function I(){return a(new Object)}function E(t,n,e){s(t)[n>>>0]=c(e)}function C(t,n){const e=function(t,n,e){if(void 0===e){const e=h.encode(t),r=n(e.length,1)>>>0;return u().subarray(r,r+e.length).set(e),b=e.length,r}let r=t.length,i=n(r,1)>>>0;const o=u();let s=0;for(;s<r;s++){const n=t.charCodeAt(s);if(n>127)break;o[i+s]=n}if(s!==r){0!==s&&(t=t.slice(s)),i=e(i,r,r=s+3*t.length,1)>>>0;const n=u().subarray(i+s,i+r);s+=p(t,n).written,i=e(i,r,s,1)>>>0}return b=s,i}(f(s(n)),r.__wbindgen_malloc,r.__wbindgen_realloc),i=b;y()[t/4+1]=i,y()[t/4+0]=e}function S(t,n){throw new Error(l(t,n))}},237:(t,n,e)=>{e.a(t,(async(t,r)=>{try{e.r(n);var i=e(941),o=t([i]);i=(o.then?(await o)():o)[0];const s=t=>{const n=document.getElementById("output-pretty"),e=document.getElementById("output-raw");if(!t.has_manifest)return n.textContent="⚠️ This file doesn't look like an add-on.",void(e.textContent="");const{cose_algorithm:r,is_cose_signed:i,is_pkcs7_signed:o,is_staging:s,kind:_,manifest:c,pkcs7_algorithm:a}=t,g=o?`<strong>${_}</strong> add-on`:"add-on";n.innerHTML=`\n    ✅ ${c.id?`This ${g} has the following ID in its manifest: <code>${c.id}</code>`:`This ${g} does not have an ID in its manifest`}. Its version is: <code>${c.version}</code>.\n    <br>\n    <br>\n    ${o?`${i?"🔐":"🔓"} It has been signed with the <strong>${s?"staging":"production"}</strong> root certificate. ${i?"This add-on is dual-signed (PKCS#7 and COSE)":"This add-on is <strong>not</strong> signed with COSE"}. The PKCS#7 digest algorithm is: <strong>${a}</strong>. ${i?`The COSE algorithm is: <strong>${r}</strong>.`:""}`:"❌ It doesn't appear to be signed."}\n        `,e.textContent=JSON.stringify({manifest:t.manifest,signatures:t.signatures},null,2)};document.getElementById("input-file").addEventListener("change",(t=>{const{files:n}=t.target,e=new FileReader;e.onload=function(t){const n=new i.OM(new Uint8Array(e.result));s(n)},e.readAsArrayBuffer(n[0])}),!1),r()}catch(t){r(t)}}))},471:(t,n,e)=>{var r=e(87);t.exports=e.v(n,t.id,"ab8ac04fa6bfd97071ef",{"./xpidump_bg.js":{__wbindgen_object_drop_ref:r.bk,__wbindgen_object_clone_ref:r.BZ,__wbindgen_string_new:r.yc,__wbg_set_f975102236d3c502:r.DK,__wbg_new_16b304a2cfa7ff4a:r.M2,__wbg_new_72fb9a18b5ae2624:r.ot,__wbg_set_d4638f722068f043:r.QU,__wbindgen_debug_string:r.rl,__wbindgen_throw:r.Qn}})}}]);