"use strict";(self.webpackChunkxpidump_webapp=self.webpackChunkxpidump_webapp||[]).push([[237],{941:(n,t,e)=>{e.a(n,(async(n,r)=>{try{e.d(t,{OM:()=>o.OM});var i=e(471),o=e(87),_=n([i]);i=(_.then?(await _)():_)[0],(0,o.lI)(i),r()}catch(n){r(n)}}))},87:(n,t,e)=>{let r;function i(n){r=n}e.d(t,{BZ:()=>I,DK:()=>T,M2:()=>C,OM:()=>x,QR:()=>$,QU:()=>j,Qg:()=>v,Qn:()=>B,Rj:()=>E,bk:()=>k,lI:()=>i,ot:()=>S,rl:()=>A,yc:()=>O}),n=e.hmd(n);const o=new Array(128).fill(void 0);function _(n){return o[n]}o.push(void 0,null,!0,!1);let s=o.length;function c(n){const t=_(n);return function(n){n<132||(o[n]=s,s=n)}(n),t}function g(n){s===o.length&&o.push(o.length+1);const t=s;return s=o[t],o[t]=n,t}let a=new("undefined"==typeof TextDecoder?(0,n.require)("util").TextDecoder:TextDecoder)("utf-8",{ignoreBOM:!0,fatal:!0});a.decode();let u=null;function d(){return null!==u&&0!==u.byteLength||(u=new Uint8Array(r.memory.buffer)),u}function l(n,t){return n>>>=0,a.decode(d().subarray(n,n+t))}function f(n){const t=typeof n;if("number"==t||"boolean"==t||null==n)return`${n}`;if("string"==t)return`"${n}"`;if("symbol"==t){const t=n.description;return null==t?"Symbol":`Symbol(${t})`}if("function"==t){const t=n.name;return"string"==typeof t&&t.length>0?`Function(${t})`:"Function"}if(Array.isArray(n)){const t=n.length;let e="[";t>0&&(e+=f(n[0]));for(let r=1;r<t;r++)e+=", "+f(n[r]);return e+="]",e}const e=/\[object ([^\]]+)\]/.exec(toString.call(n));let r;if(!(e.length>1))return toString.call(n);if(r=e[1],"Object"==r)try{return"Object("+JSON.stringify(n)+")"}catch(n){return"Object"}return n instanceof Error?`${n.name}: ${n.message}\n${n.stack}`:r}let b=0,w=new("undefined"==typeof TextEncoder?(0,n.require)("util").TextEncoder:TextEncoder)("utf-8");const h="function"==typeof w.encodeInto?function(n,t){return w.encodeInto(n,t)}:function(n,t){const e=w.encode(n);return t.set(e),{read:n.length,written:e.length}};let p=null;function y(){return null!==p&&0!==p.byteLength||(p=new Int32Array(r.memory.buffer)),p}const m="undefined"==typeof FinalizationRegistry?{register:()=>{},unregister:()=>{}}:new FinalizationRegistry((n=>r.__wbg_xpi_free(n>>>0)));class x{__destroy_into_raw(){const n=this.__wbg_ptr;return this.__wbg_ptr=0,m.unregister(this),n}free(){const n=this.__destroy_into_raw();r.__wbg_xpi_free(n)}constructor(n){const t=function(n,t){const e=t(1*n.length,1)>>>0;return d().set(n,e/1),b=n.length,e}(n,r.__wbindgen_malloc),e=b,i=r.xpi_new(t,e);return this.__wbg_ptr=i>>>0,this}get manifest(){return c(r.xpi_manifest(this.__wbg_ptr))}get signatures(){return c(r.xpi_signatures(this.__wbg_ptr))}get has_manifest(){return 0!==r.xpi_has_manifest(this.__wbg_ptr)}get is_pkcs7_signed(){return 0!==r.xpi_is_pkcs7_signed(this.__wbg_ptr)}get is_staging(){return 0!==r.xpi_is_staging(this.__wbg_ptr)}get pkcs7_algorithm(){let n,t;try{const o=r.__wbindgen_add_to_stack_pointer(-16);r.xpi_pkcs7_algorithm(o,this.__wbg_ptr);var e=y()[o/4+0],i=y()[o/4+1];return n=e,t=i,l(e,i)}finally{r.__wbindgen_add_to_stack_pointer(16),r.__wbindgen_free(n,t,1)}}get kind(){let n,t;try{const o=r.__wbindgen_add_to_stack_pointer(-16);r.xpi_kind(o,this.__wbg_ptr);var e=y()[o/4+0],i=y()[o/4+1];return n=e,t=i,l(e,i)}finally{r.__wbindgen_add_to_stack_pointer(16),r.__wbindgen_free(n,t,1)}}get is_cose_signed(){return 0!==r.xpi_is_cose_signed(this.__wbg_ptr)}get cose_algorithm(){let n,t;try{const o=r.__wbindgen_add_to_stack_pointer(-16);r.xpi_cose_algorithm(o,this.__wbg_ptr);var e=y()[o/4+0],i=y()[o/4+1];return n=e,t=i,l(e,i)}finally{r.__wbindgen_add_to_stack_pointer(16),r.__wbindgen_free(n,t,1)}}}function k(n){c(n)}function $(n){return g(n)}function v(n){return g(BigInt.asUintN(64,n))}function I(n){return g(_(n))}function O(n,t){return g(l(n,t))}function T(n,t,e){_(n)[c(t)]=c(e)}function E(n,t){return g(new Error(l(n,t)))}function C(){return g(new Array)}function S(){return g(new Object)}function j(n,t,e){_(n)[t>>>0]=c(e)}function A(n,t){const e=function(n,t,e){if(void 0===e){const e=w.encode(n),r=t(e.length,1)>>>0;return d().subarray(r,r+e.length).set(e),b=e.length,r}let r=n.length,i=t(r,1)>>>0;const o=d();let _=0;for(;_<r;_++){const t=n.charCodeAt(_);if(t>127)break;o[i+_]=t}if(_!==r){0!==_&&(n=n.slice(_)),i=e(i,r,r=_+3*n.length,1)>>>0;const t=d().subarray(i+_,i+r);_+=h(n,t).written,i=e(i,r,_,1)>>>0}return b=_,i}(f(_(t)),r.__wbindgen_malloc,r.__wbindgen_realloc),i=b;y()[n/4+1]=i,y()[n/4+0]=e}function B(n,t){throw new Error(l(n,t))}},237:(n,t,e)=>{e.a(n,(async(n,r)=>{try{e.r(t);var i=e(941),o=n([i]);i=(o.then?(await o)():o)[0];const _=n=>{const t=document.getElementById("output-pretty"),e=document.getElementById("output-raw");if(!n.has_manifest)return t.textContent="⚠️ This file doesn't look like an add-on.",void(e.textContent="");const{cose_algorithm:r,is_cose_signed:i,is_pkcs7_signed:o,is_staging:_,kind:s,manifest:c,pkcs7_algorithm:g}=n,a=o?`<strong>${s}</strong> add-on`:"add-on";t.innerHTML=`\n    ✅ ${c.id?`This ${a} has the following ID in its manifest: <code>${c.id}</code>`:`This ${a} does not have an ID in its manifest`}. Its version is: <code>${c.version}</code>.\n    <br>\n    <br>\n    ${o?`${i?"🔐":"🔓"} It has been signed with the <strong>${_?"staging":"production"}</strong> root certificate. ${i?"This add-on is dual-signed (PKCS#7 and COSE)":"This add-on is <strong>not</strong> signed with COSE"}. The PKCS#7 digest algorithm is: <strong>${g}</strong>. ${i?`The COSE algorithm is: <strong>${r}</strong>.`:""}`:"❌ It doesn't appear to be signed."}\n        `,e.textContent=JSON.stringify({manifest:n.manifest,signatures:n.signatures},null,2)};document.getElementById("input-file").addEventListener("change",(n=>{const{files:t}=n.target,e=new FileReader;e.onload=function(n){const t=new i.OM(new Uint8Array(e.result));_(t)},e.readAsArrayBuffer(t[0])}),!1),r()}catch(n){r(n)}}))},471:(n,t,e)=>{var r=e(87);n.exports=e.v(t,n.id,"f92c9fa01992cf539203",{"./xpidump_bg.js":{__wbindgen_object_drop_ref:r.bk,__wbindgen_number_new:r.QR,__wbindgen_bigint_from_u64:r.Qg,__wbindgen_object_clone_ref:r.BZ,__wbindgen_string_new:r.yc,__wbg_set_f975102236d3c502:r.DK,__wbindgen_error_new:r.Rj,__wbg_new_16b304a2cfa7ff4a:r.M2,__wbg_new_72fb9a18b5ae2624:r.ot,__wbg_set_d4638f722068f043:r.QU,__wbindgen_debug_string:r.rl,__wbindgen_throw:r.Qn}})}}]);