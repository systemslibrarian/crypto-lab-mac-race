(function(){const e=document.createElement("link").relList;if(e&&e.supports&&e.supports("modulepreload"))return;for(const r of document.querySelectorAll('link[rel="modulepreload"]'))n(r);new MutationObserver(r=>{for(const s of r)if(s.type==="childList")for(const i of s.addedNodes)i.tagName==="LINK"&&i.rel==="modulepreload"&&n(i)}).observe(document,{childList:!0,subtree:!0});function a(r){const s={};return r.integrity&&(s.integrity=r.integrity),r.referrerPolicy&&(s.referrerPolicy=r.referrerPolicy),r.crossOrigin==="use-credentials"?s.credentials="include":r.crossOrigin==="anonymous"?s.credentials="omit":s.credentials="same-origin",s}function n(r){if(r.ep)return;r.ep=!0;const s=a(r);fetch(r.href,s)}})();const je=new TextEncoder,x=16,Fe=135;function D(t){return Array.from(t,e=>e.toString(16).padStart(2,"0")).join("")}function ke(t){const e=t.trim().toLowerCase();if(!/^[0-9a-f]*$/.test(e)||e.length%2!==0)throw new Error("Expected an even-length hex string");const a=new Uint8Array(e.length/2);for(let n=0;n<a.length;n+=1)a[n]=Number.parseInt(e.slice(n*2,n*2+2),16);return a}function ct(t){return/^[0-9a-fA-F]+$/.test(t)&&t.length%2===0}async function lt(t){const e=t.trim();if(!e)throw new Error("CMAC key is required");if(ct(e)&&e.length===64)return ke(e);const a=await crypto.subtle.digest("SHA-256",je.encode(t));return new Uint8Array(a)}function ve(t,e){const a=new Uint8Array(x);for(let n=0;n<x;n+=1)a[n]=t[n]^e[n];return a}function Ke(t){const e=new Uint8Array(x);let a=0;for(let n=x-1;n>=0;n-=1){const r=t[n];e[n]=r<<1&255|a,a=(r&128)>>>7}return e}async function Ce(t,e){const a=await crypto.subtle.importKey("raw",t,{name:"AES-CBC"},!1,["encrypt"]),n=new Uint8Array(x),r=await crypto.subtle.encrypt({name:"AES-CBC",iv:n},a,e);return new Uint8Array(r).slice(0,x)}async function dt(t){const e=new Uint8Array(x),a=await Ce(t,e);let n=Ke(a);a[0]&128&&(n[x-1]^=Fe);let r=Ke(n);return n[0]&128&&(r[x-1]^=Fe),{k1:n,k2:r}}function ut(t){if(t.length===0)return[new Uint8Array(0)];const e=[];for(let a=0;a<t.length;a+=x)e.push(t.slice(a,a+x));return e}function ft(t){const e=new Uint8Array(x);return e.set(t,0),e[t.length]=128,e}async function We(t,e){return Xe(je.encode(t),e)}async function Xe(t,e){const a=await lt(e),{k1:n,k2:r}=await dt(a),s=ut(t),i=s.length-1,o=t.length!==0&&t.length%x===0,l=s[i],u=o?l:ft(l),d=ve(u,o?n:r);let f=new Uint8Array(x);const h=[];for(let p=0;p<i;p+=1)f=await Ce(a,ve(f,s[p])),h.push(D(f));const y=await Ce(a,ve(f,d));return{tagHex:D(y),details:{keyHex:D(a),k1Hex:D(n),k2Hex:D(r),paddedLastBlockHex:D(u),finalXorBlockHex:D(d),chainingHex:h}}}async function ht(t,e,a){try{const r=(await We(t,e)).tagHex.toLowerCase(),s=a.trim().toLowerCase();if(r.length!==s.length)return!1;let i=0;for(let o=0;o<r.length;o+=1)i|=r.charCodeAt(o)^s.charCodeAt(o);return i===0}catch{return!1}}async function gt(){const t="603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",e="6bc1bee22e409f96e93d7e117393172a",a="28a7023f452e8f82bd4bf28d8c37c35c",n=ke(t),r=await Xe(ke(e),t);return D(n)===r.details.keyHex&&r.tagHex===a}/*! noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com) */function Qe(t){return t instanceof Uint8Array||ArrayBuffer.isView(t)&&t.constructor.name==="Uint8Array"}function fe(t,...e){if(!Qe(t))throw new Error("Uint8Array expected");if(e.length>0&&!e.includes(t.length))throw new Error("Uint8Array expected of length "+e+", got length="+t.length)}function Ne(t,e=!0){if(t.destroyed)throw new Error("Hash instance has been destroyed");if(e&&t.finished)throw new Error("Hash#digest() has already been called")}function pt(t,e){fe(t);const a=e.outputLen;if(t.length<a)throw new Error("digestInto() expects output buffer of length at least "+a)}function De(...t){for(let e=0;e<t.length;e++)t[e].fill(0)}const Ye=typeof Uint8Array.from([]).toHex=="function"&&typeof Uint8Array.fromHex=="function",mt=Array.from({length:256},(t,e)=>e.toString(16).padStart(2,"0"));function R(t){if(fe(t),Ye)return t.toHex();let e="";for(let a=0;a<t.length;a++)e+=mt[t[a]];return e}const G={_0:48,_9:57,A:65,F:70,a:97,f:102};function Oe(t){if(t>=G._0&&t<=G._9)return t-G._0;if(t>=G.A&&t<=G.F)return t-(G.A-10);if(t>=G.a&&t<=G.f)return t-(G.a-10)}function _(t){if(typeof t!="string")throw new Error("hex string expected, got "+typeof t);if(Ye)return Uint8Array.fromHex(t);const e=t.length,a=e/2;if(e%2)throw new Error("hex string expected, got unpadded hex of length "+e);const n=new Uint8Array(a);for(let r=0,s=0;r<a;r++,s+=2){const i=Oe(t.charCodeAt(s)),o=Oe(t.charCodeAt(s+1));if(i===void 0||o===void 0){const l=t[s]+t[s+1];throw new Error('hex string expected, got non-hex character "'+l+'" at index '+s)}n[r]=i*16+o}return n}function yt(t){if(typeof t!="string")throw new Error("string expected");return new Uint8Array(new TextEncoder().encode(t))}function Se(t){if(typeof t=="string")t=yt(t);else if(Qe(t))t=bt(t);else throw new Error("Uint8Array expected, got "+typeof t);return t}function bt(t){return Uint8Array.from(t)}const w=16,vt=0xe1000000000000000000000000000000n,wt=(1n<<128n)-1n;function he(t,e){const a=new Uint8Array(w);for(let n=0;n<w;n+=1)a[n]=t[n]^e[n];return a}function qe(t){let e=0n;for(const a of t)e=(e<<8n)+BigInt(a);return e}function xt(t){const e=new Uint8Array(w);let a=t&wt;for(let n=w-1;n>=0;n-=1)e[n]=Number(a&0xffn),a>>=8n;return e}function I(t,e){let a=qe(t),n=qe(e),r=0n;for(let s=0;s<128;s+=1){(a&1n<<BigInt(127-s))!==0n&&(r^=n);const i=n&1n;n>>=1n,i&&(n^=vt)}return xt(r)}function At(t,e){const a=new Uint8Array(w),n=BigInt(t)*8n,r=BigInt(e)*8n;for(let s=0;s<8;s+=1)a[7-s]=Number(n>>BigInt(s*8)&0xffn),a[15-s]=Number(r>>BigInt(s*8)&0xffn);return a}function Ht(t){const e=[];for(let a=0;a<t.length;a+=w){const n=new Uint8Array(w);n.set(t.slice(a,a+w),0),e.push(n)}return t.length===0&&e.push(new Uint8Array(w)),e}async function kt(t,e){const a=await crypto.subtle.importKey("raw",t,{name:"AES-CBC"},!1,["encrypt"]),n=new Uint8Array(w),r=await crypto.subtle.encrypt({name:"AES-CBC",iv:n},a,e);return new Uint8Array(r).slice(0,w)}async function Ct(t,e){const a=_(t),n=crypto.getRandomValues(new Uint8Array(16)),r=await kt(n,new Uint8Array(w));let s=new Uint8Array(w);const i=[];for(const l of Ht(a))s=I(he(s,l),r),i.push(R(s));const o=At(0,a.length);return s=I(he(s,o),r),i.push(R(s)),{hHex:R(r),yHex:R(s),steps:i}}function St(t){return I(t,t)}function Et(t){let e=(1n<<128n)-2n,a=t,n=new Uint8Array(w);for(n[0]=128;e>0n;)(e&1n)===1n&&(n=I(n,a)),a=St(a),e>>=1n;return n}function Mt(){const t=_("66e94bd4ef8a2c3b884cfa59ca342b2e"),e=_("0388dace60b6a392f328c2b971b2fe78"),a=_("42831ec2217774244b7221b784d0d49c"),n=I(e,t),r=I(a,t),s=he(e,a),i=he(n,r),o=I(i,Et(s)),l=_("feedfacedeadbeeffeedfacedeadbeef"),u=I(l,o),d=I(l,t);return{deltaCHex:R(s),deltaTHex:R(i),recoveredHHex:R(o),forgedValid:R(u)===R(d),note:"Nonce reuse leaks linear equations in GHASH; with enough structure, H can be solved and forgeries follow."}}function Tt(){const t=_("66e94bd4ef8a2c3b884cfa59ca342b2e"),e=_("0388dace60b6a392f328c2b971b2fe78");return R(I(e,t))==="5e2ec746917062882c85b0685353deb7"}const Be=new TextEncoder;function F(t){return Array.from(t,e=>e.toString(16).padStart(2,"0")).join("")}function $t(t){const e=t.trim().toLowerCase();if(!/^[0-9a-f]*$/.test(e)||e.length%2!==0)throw new Error("Expected an even-length hex string");const a=new Uint8Array(e.length/2);for(let n=0;n<a.length;n+=1)a[n]=Number.parseInt(e.slice(n*2,n*2+2),16);return a}function Lt(t){return/^[0-9a-fA-F]+$/.test(t)&&t.length%2===0}function Je(t){const e=t.trim();if(e.length===0)throw new Error("Key must not be empty");return Lt(e)?$t(e):Be.encode(t)}async function we(t,e){const a=await crypto.subtle.digest(t,e);return new Uint8Array(a)}function Ve(t,e){const a=new Uint8Array(t.length+e.length);return a.set(t,0),a.set(e,t.length),a}async function Bt(t,e,a){const n=t==="SHA-256"?64:128,r=new Uint8Array(n),s=e.length>n?await we(t,e):e;r.set(s.slice(0,n));const i=new Uint8Array(n),o=new Uint8Array(n);for(let d=0;d<n;d+=1)i[d]=r[d]^54,o[d]=r[d]^92;const l=await we(t,Ve(i,a)),u=await we(t,Ve(o,l));return{normalizedKeyHex:F(r),ipadHex:F(i),opadHex:F(o),innerHashHex:F(l),outerHashHex:F(u)}}async function re(t,e,a){const n=Be.encode(t),r=Je(e),s=await crypto.subtle.importKey("raw",r,{name:"HMAC",hash:a},!1,["sign"]),i=await crypto.subtle.sign("HMAC",s,n),o=F(new Uint8Array(i)),l=await Bt(a,r,n);return{macHex:o,visual:l}}function Ut(t,e){if(t.length!==e.length)return!1;let a=0;for(let n=0;n<t.length;n+=1)a|=t.charCodeAt(n)^e.charCodeAt(n);return a===0}async function Rt(t,e,a,n){try{const r=await re(t,e,a);return Ut(r.macHex.toLowerCase(),n.trim().toLowerCase())}catch{return!1}}async function It(t,e){const a=Be.encode(t||"A"),n=Je(e||"default-key"),r=new Uint8Array(a);r[0]^=1;const s=new Uint8Array(n);s[0]^=1;const i=await re(t||"A",e||"default-key","SHA-256"),o=await crypto.subtle.importKey("raw",n,{name:"HMAC",hash:"SHA-256"},!1,["sign"]),l=await crypto.subtle.importKey("raw",s,{name:"HMAC",hash:"SHA-256"},!1,["sign"]),u=await crypto.subtle.sign("HMAC",o,r),d=await crypto.subtle.sign("HMAC",l,a);return{original:i.macHex,flippedMessage:F(new Uint8Array(u)),flippedKey:F(new Uint8Array(d))}}async function Pt(){const t=new Uint8Array(20).fill(11),e=F(t),a="Hi There",n="b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",r="87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",s=await re(a,e,"SHA-256"),i=await re(a,e,"SHA-512");return s.macHex===n&&i.macHex===r}const le=new TextEncoder,Gt=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298];function P(t,e){return t>>>e|t<<32-e}function Ft(t,e,a){return t&e^~t&a}function Kt(t,e,a){return t&e^t&a^e&a}function Nt(t){return P(t,2)^P(t,13)^P(t,22)}function Dt(t){return P(t,6)^P(t,11)^P(t,25)}function Ot(t){return P(t,7)^P(t,18)^t>>>3}function qt(t){return P(t,17)^P(t,19)^t>>>10}function de(t){return Array.from(t,e=>e.toString(16).padStart(2,"0")).join("")}function Vt(t){const e=t.trim().toLowerCase();if(!/^[0-9a-f]*$/.test(e)||e.length%2!==0)throw new Error("Expected hex string");const a=new Uint8Array(e.length/2);for(let n=0;n<a.length;n+=1)a[n]=Number.parseInt(e.slice(n*2,n*2+2),16);return a}function ge(t){const e=BigInt(t)*8n,a=(t+1)%64,n=a<=56?56-a:56+(64-a),r=new Uint8Array(1+n+8);r[0]=128;for(let s=0;s<8;s+=1)r[r.length-1-s]=Number(e>>BigInt(s*8)&0xffn);return r}function _t(t){const e=Vt(t);if(e.length!==32)throw new Error("SHA-256 digest must be 32 bytes");const a=new Uint32Array(8),n=new DataView(e.buffer);for(let r=0;r<8;r+=1)a[r]=n.getUint32(r*4,!1);return a}function zt(t){const e=new Uint8Array(32),a=new DataView(e.buffer);for(let n=0;n<8;n+=1)a.setUint32(n*4,t[n],!1);return de(e)}function jt(t,e){const a=new Uint32Array(64),n=new DataView(e.buffer,e.byteOffset,e.byteLength);for(let h=0;h<16;h+=1)a[h]=n.getUint32(h*4,!1);for(let h=16;h<64;h+=1)a[h]=qt(a[h-2])+a[h-7]+Ot(a[h-15])+a[h-16]>>>0;let[r,s,i,o,l,u,d,f]=t;for(let h=0;h<64;h+=1){const y=f+Dt(l)+Ft(l,u,d)+Gt[h]+a[h]>>>0,p=Nt(r)+Kt(r,s,i)>>>0;f=d,d=u,u=l,l=o+y>>>0,o=i,i=s,s=r,r=y+p>>>0}t[0]=t[0]+r>>>0,t[1]=t[1]+s>>>0,t[2]=t[2]+i>>>0,t[3]=t[3]+o>>>0,t[4]=t[4]+l>>>0,t[5]=t[5]+u>>>0,t[6]=t[6]+d>>>0,t[7]=t[7]+f>>>0}function Ee(t,e,a){const n=_t(t),r=e+a.length,s=new Uint8Array(a.length+ge(r).length);s.set(a,0),s.set(ge(r),a.length);for(let i=0;i<s.length;i+=64)jt(n,s.slice(i,i+64));return zt(n)}function O(t,e){const a=new Uint8Array(t.length+e.length);return a.set(t,0),a.set(e,t.length),a}async function pe(t){const e=await crypto.subtle.digest("SHA-256",t);return de(new Uint8Array(e))}async function Ze(t,e){const a=await crypto.subtle.importKey("raw",t,{name:"HMAC",hash:"SHA-256"},!1,["sign"]),n=await crypto.subtle.sign("HMAC",a,e);return de(new Uint8Array(n))}let K=et();function et(){const t=8+Math.floor(Math.random()*17);return crypto.getRandomValues(new Uint8Array(t))}function Wt(){return K=et(),K.length}function Xt(){return K.length}const ae=[8,24];async function Qt(t){const e=le.encode(t),a=await pe(O(K,e)),n=await Ze(K,e);return{rawMacHex:a,hmacMacHex:n}}async function tt(t,e){const a=await pe(O(K,t));return nt(a,e)}async function at(t,e){const a=await Ze(K,t);return nt(a,e)}function nt(t,e){const a=t.toLowerCase(),n=e.trim().toLowerCase();if(a.length!==n.length)return!1;let r=0;for(let s=0;s<a.length;s+=1)r|=a.charCodeAt(s)^n.charCodeAt(s);return r===0}async function Yt(t,e,a,n,r){const s=le.encode(t),i=le.encode(n),o=ge(r+s.length),l=O(O(s,o),i),u=r+s.length+o.length,d=Ee(e,u,i),f=Ee(a,u,i),h=await tt(l,d),y=await at(l,f);return{guessedSecretLength:r,actualSecretLength:K.length,forgedMessageHex:de(l),forgedMessageVisible:Jt(l),forgedRawTagHex:d,forgedHmacTagAttemptHex:f,rawServerAccepts:h,hmacServerAccepts:y,guessCorrect:r===K.length}}function Jt(t){let e="";for(const a of t)a>=32&&a<=126?e+=String.fromCharCode(a):e+=`\\x${a.toString(16).padStart(2,"0")}`;return e}async function Zt(t,e,a=16){const n=crypto.getRandomValues(new Uint8Array(a)),r=le.encode(t),s=le.encode(e),i=await pe(O(n,r)),o=ge(n.length+r.length),l=O(O(r,o),s),u=n.length+r.length+o.length,d=Ee(i,u,s),f=await pe(O(n,l));return{originalMessage:t,appendMessage:e,originalMacHex:i,forgedMacHex:d,forgedMessageHex:de(l),verificationMacHex:f,valid:d===f,guessedSecretLength:a}}async function ea(){return(await Zt("comment=10&uid=7","&admin=true",16)).valid}const b=(t,e)=>t[e++]&255|(t[e++]&255)<<8;class ta{constructor(e){this.blockLen=16,this.outputLen=16,this.buffer=new Uint8Array(16),this.r=new Uint16Array(10),this.h=new Uint16Array(10),this.pad=new Uint16Array(8),this.pos=0,this.finished=!1,e=Se(e),fe(e,32);const a=b(e,0),n=b(e,2),r=b(e,4),s=b(e,6),i=b(e,8),o=b(e,10),l=b(e,12),u=b(e,14);this.r[0]=a&8191,this.r[1]=(a>>>13|n<<3)&8191,this.r[2]=(n>>>10|r<<6)&7939,this.r[3]=(r>>>7|s<<9)&8191,this.r[4]=(s>>>4|i<<12)&255,this.r[5]=i>>>1&8190,this.r[6]=(i>>>14|o<<2)&8191,this.r[7]=(o>>>11|l<<5)&8065,this.r[8]=(l>>>8|u<<8)&8191,this.r[9]=u>>>5&127;for(let d=0;d<8;d++)this.pad[d]=b(e,16+2*d)}process(e,a,n=!1){const r=n?0:2048,{h:s,r:i}=this,o=i[0],l=i[1],u=i[2],d=i[3],f=i[4],h=i[5],y=i[6],p=i[7],A=i[8],H=i[9],me=b(e,a+0),ye=b(e,a+2),Ue=b(e,a+4),Re=b(e,a+6),be=b(e,a+8),Ie=b(e,a+10),Pe=b(e,a+12),Ge=b(e,a+14);let k=s[0]+(me&8191),C=s[1]+((me>>>13|ye<<3)&8191),S=s[2]+((ye>>>10|Ue<<6)&8191),E=s[3]+((Ue>>>7|Re<<9)&8191),M=s[4]+((Re>>>4|be<<12)&8191),T=s[5]+(be>>>1&8191),$=s[6]+((be>>>14|Ie<<2)&8191),L=s[7]+((Ie>>>11|Pe<<5)&8191),B=s[8]+((Pe>>>8|Ge<<8)&8191),U=s[9]+(Ge>>>5|r),g=0,N=g+k*o+C*(5*H)+S*(5*A)+E*(5*p)+M*(5*y);g=N>>>13,N&=8191,N+=T*(5*h)+$*(5*f)+L*(5*d)+B*(5*u)+U*(5*l),g+=N>>>13,N&=8191;let V=g+k*l+C*o+S*(5*H)+E*(5*A)+M*(5*p);g=V>>>13,V&=8191,V+=T*(5*y)+$*(5*h)+L*(5*f)+B*(5*d)+U*(5*u),g+=V>>>13,V&=8191;let j=g+k*u+C*l+S*o+E*(5*H)+M*(5*A);g=j>>>13,j&=8191,j+=T*(5*p)+$*(5*y)+L*(5*h)+B*(5*f)+U*(5*d),g+=j>>>13,j&=8191;let W=g+k*d+C*u+S*l+E*o+M*(5*H);g=W>>>13,W&=8191,W+=T*(5*A)+$*(5*p)+L*(5*y)+B*(5*h)+U*(5*f),g+=W>>>13,W&=8191;let X=g+k*f+C*d+S*u+E*l+M*o;g=X>>>13,X&=8191,X+=T*(5*H)+$*(5*A)+L*(5*p)+B*(5*y)+U*(5*h),g+=X>>>13,X&=8191;let Q=g+k*h+C*f+S*d+E*u+M*l;g=Q>>>13,Q&=8191,Q+=T*o+$*(5*H)+L*(5*A)+B*(5*p)+U*(5*y),g+=Q>>>13,Q&=8191;let Y=g+k*y+C*h+S*f+E*d+M*u;g=Y>>>13,Y&=8191,Y+=T*l+$*o+L*(5*H)+B*(5*A)+U*(5*p),g+=Y>>>13,Y&=8191;let J=g+k*p+C*y+S*h+E*f+M*d;g=J>>>13,J&=8191,J+=T*u+$*l+L*o+B*(5*H)+U*(5*A),g+=J>>>13,J&=8191;let Z=g+k*A+C*p+S*y+E*h+M*f;g=Z>>>13,Z&=8191,Z+=T*d+$*u+L*l+B*o+U*(5*H),g+=Z>>>13,Z&=8191;let ee=g+k*H+C*A+S*p+E*y+M*h;g=ee>>>13,ee&=8191,ee+=T*f+$*d+L*u+B*l+U*o,g+=ee>>>13,ee&=8191,g=(g<<2)+g|0,g=g+N|0,N=g&8191,g=g>>>13,V+=g,s[0]=N,s[1]=V,s[2]=j,s[3]=W,s[4]=X,s[5]=Q,s[6]=Y,s[7]=J,s[8]=Z,s[9]=ee}finalize(){const{h:e,pad:a}=this,n=new Uint16Array(10);let r=e[1]>>>13;e[1]&=8191;for(let o=2;o<10;o++)e[o]+=r,r=e[o]>>>13,e[o]&=8191;e[0]+=r*5,r=e[0]>>>13,e[0]&=8191,e[1]+=r,r=e[1]>>>13,e[1]&=8191,e[2]+=r,n[0]=e[0]+5,r=n[0]>>>13,n[0]&=8191;for(let o=1;o<10;o++)n[o]=e[o]+r,r=n[o]>>>13,n[o]&=8191;n[9]-=8192;let s=(r^1)-1;for(let o=0;o<10;o++)n[o]&=s;s=~s;for(let o=0;o<10;o++)e[o]=e[o]&s|n[o];e[0]=(e[0]|e[1]<<13)&65535,e[1]=(e[1]>>>3|e[2]<<10)&65535,e[2]=(e[2]>>>6|e[3]<<7)&65535,e[3]=(e[3]>>>9|e[4]<<4)&65535,e[4]=(e[4]>>>12|e[5]<<1|e[6]<<14)&65535,e[5]=(e[6]>>>2|e[7]<<11)&65535,e[6]=(e[7]>>>5|e[8]<<8)&65535,e[7]=(e[8]>>>8|e[9]<<5)&65535;let i=e[0]+a[0];e[0]=i&65535;for(let o=1;o<8;o++)i=(e[o]+a[o]|0)+(i>>>16)|0,e[o]=i&65535;De(n)}update(e){Ne(this),e=Se(e),fe(e);const{buffer:a,blockLen:n}=this,r=e.length;for(let s=0;s<r;){const i=Math.min(n-this.pos,r-s);if(i===n){for(;n<=r-s;s+=n)this.process(e,s);continue}a.set(e.subarray(s,s+i),this.pos),this.pos+=i,s+=i,this.pos===n&&(this.process(a,0,!1),this.pos=0)}return this}destroy(){De(this.h,this.r,this.buffer,this.pad)}digestInto(e){Ne(this),pt(e,this),this.finished=!0;const{buffer:a,h:n}=this;let{pos:r}=this;if(r){for(a[r++]=1;r<16;r++)a[r]=0;this.process(a,0,!0)}this.finalize();let s=0;for(let i=0;i<8;i++)e[s++]=n[i]>>>0,e[s++]=n[i]>>>8;return e}digest(){const{buffer:e,outputLen:a}=this;this.digestInto(e);const n=e.slice(0,a);return this.destroy(),n}}function aa(t){const e=(n,r)=>t(r).update(Se(n)).digest(),a=t(new Uint8Array(32));return e.outputLen=a.outputLen,e.blockLen=a.blockLen,e.create=n=>t(n),e}const oe=aa(t=>new ta(t)),ie=new TextEncoder,xe=new TextDecoder,na=(1n<<130n)-5n,se=1n<<128n;function ne(t){return Array.from(t,e=>e.toString(16).padStart(2,"0")).join("")}function ra(t){const e=t.trim().toLowerCase();if(!/^[0-9a-f]*$/.test(e)||e.length%2!==0)throw new Error("Expected an even-length hex string");const a=new Uint8Array(e.length/2);for(let n=0;n<a.length;n+=1)a[n]=Number.parseInt(e.slice(n*2,n*2+2),16);return a}function Me(t){let e=0n;for(let a=t.length-1;a>=0;a-=1)e=(e<<8n)+BigInt(t[a]);return e}function sa(t,e){let a=t;const n=new Uint8Array(e);for(let r=0;r<e;r+=1)n[r]=Number(a&0xffn),a>>=8n;return n}function oa(t){const e=new Uint8Array(17);return e.set(t,0),e[t.length]=1,Me(e)}function Ae(t,e){return oa(t)*e%na}function rt(){const t=new Uint8Array(32);crypto.getRandomValues(t),t[2]=0,t[3]=0;for(let e=4;e<16;e+=1)t[e]=0;return t}function ia(t,e){if(t.length!==e.length)return!1;let a=0;for(let n=0;n<t.length;n+=1)a|=t[n]^e[n];return a===0}function ca(t,e){const a=ie.encode(t),n=rt();if(n.length!==32)throw new Error("Poly1305 key must be exactly 32 bytes (64 hex chars)");const r=oe(a,n);return{tagHex:ne(r),keyHex:ne(n),notes:"Poly1305 key is one-time only. Reusing it breaks authenticity guarantees."}}function la(){const t=rt(),e=ie.encode("Invoice=1000USD"),a=ie.encode("Invoice=9000USD"),n=ie.encode("Invoice=9999USD"),r=oe(e,t),s=oe(a,t),i=Me(r),o=Me(s);let l=-1n,u=0n;for(let p=0n;p<=0xffffn;p+=1n){const A=Ae(e,p),H=((i-A)%se+se)%se;if((Ae(a,p)+H)%se===o){l=p,u=H;break}}if(l<0n)throw new Error("Failed to recover weak Poly1305 key; retry demo");const f=(Ae(n,l)+u)%se,h=sa(f,16),y=oe(n,t);return{msg1:xe.decode(e),msg2:xe.decode(a),msg3:xe.decode(n),tag1Hex:ne(r),tag2Hex:ne(s),forgedTagHex:ne(h),validForgery:ia(h,y),recoveredRHex:l.toString(16).padStart(4,"0")}}function da(){const t=ra("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),e=ie.encode("Cryptographic Forum Research Group"),a="a8061dc1305136c6c22b8baf0c0127a9",n=oe(e,t);return ne(n)===a}function z(t){return new TextEncoder().encode(t)}function Te(t,e){if(t.length!==e.length)return!1;for(let a=0;a<t.length;a+=1)if(t[a]!==e[a])return!1;return!0}function $e(t,e){if(t.length!==e.length)return!1;let a=0;for(let n=0;n<t.length;n+=1)a|=t[n]^e[n];return a===0}function _e(t,e,a,n){const r=performance.now();for(let i=0;i<n;i+=1)t(e,a);return performance.now()-r}function ua(t=5e4){const e=z("mac=5f93b8f7ccf93f2af1b047b4f4e8a2d3");return{rows:[{label:"Mismatch at byte 1",value:z("Xac=5f93b8f7ccf93f2af1b047b4f4e8a2d3")},{label:"Mismatch at middle",value:z("mac=5f93b8f7ccf93f2af1b04700f4e8a2d3")},{label:"Mismatch at final byte",value:z("mac=5f93b8f7ccf93f2af1b047b4f4e8a2d4")}].map(r=>({label:r.label,naiveMs:_e(Te,e,r.value,t),constantMs:_e($e,e,r.value,t)})),summary:"Naive comparison exits early and leaks prefix-match timing. Constant-time comparison keeps timing flatter."}}function ue(t){return Array.from(t,e=>e.toString(16).padStart(2,"0")).join("")}function fa(t){const e=crypto.getRandomValues(new Uint8Array(t));let a=0;return{trueTag:e,queries:()=>a,measure(n){a+=1;let r=0;for(let s=0;s<e.length&&(r+=1,e[s]===n[s]);s+=1);return r}}}async function ha(t=16,e,a){const n=Math.min(a??t,t),r=fa(t),s=new Uint8Array(t);for(let l=0;l<n;l+=1){let u=0,d=-1;for(let f=0;f<256;f+=1){s[l]=f;const h=r.measure(s);h>d&&(d=h,u=f)}s[l]=u,e&&e({byteIndex:l,byteValue:u,recoveredHex:ue(s.slice(0,l+1)),totalBytes:t,oracleQueries:r.queries()}),await new Promise(f=>setTimeout(f,35))}const i=ue(s.slice(0,n)),o=ue(r.trueTag.slice(0,n));return{trueTagHex:ue(r.trueTag),recoveredTagHex:i,bytesRecovered:n,totalBytes:t,oracleQueries:r.queries(),success:i===o}}function ga(){const t=z("abcdef"),e=z("abcdef"),a=z("abcdeg");return Te(t,e)&&!Te(t,a)&&$e(t,e)&&!$e(t,a)}function c(t){const e=document.getElementById(t);if(!e)throw new Error(`Missing element: ${t}`);return e}function m(t,e=!1){const a=c("aria-live");a.textContent=t,a.dataset.kind=e?"error":"ok"}function ce(t,e=128){return t.length>e?`${t.slice(0,e)}...`:t}function st(t,e){t.textContent="";const a=e.map(r=>{const s=document.createElement("div");return s.className="step-line",s.textContent=r,s.hidden=!0,t.appendChild(s),s});let n=0;return{step(){return n>=a.length?!1:(a[n].hidden=!1,a[n].classList.add("step-line-new"),n+=1,n<a.length)},revealAll(){for(let r=n;r<a.length;r+=1)a[r].hidden=!1;n=a.length},reset(){for(const r of a)r.hidden=!0;n=0}}}function ze(t,e,a,n){t.textContent="";const r=Le(e),s=Le(a),i=document.createElement("div");i.className="bitdiff-grid",i.setAttribute("role","img");let o=0;const l=Math.min(r.length,s.length)*8;for(let f=0;f<Math.min(r.length,s.length);f+=1){const h=r[f]^s[f];for(let y=7;y>=0;y-=1){const p=document.createElement("span");p.className="bitdiff-cell",(h>>y&1)===1&&(p.classList.add("bitdiff-flip"),o+=1),i.appendChild(p)}}const u=l===0?0:o/l*100,d=document.createElement("p");d.className="bitdiff-label",d.textContent=`${n} — ${o}/${l} bits flipped (${u.toFixed(1)}%)`,t.appendChild(i),t.appendChild(d),i.setAttribute("aria-label",d.textContent)}function Le(t){const e=t.toLowerCase().replace(/[^0-9a-f]/g,""),a=new Uint8Array(Math.floor(e.length/2));for(let n=0;n<a.length;n+=1)a[n]=Number.parseInt(e.slice(n*2,n*2+2),16);return a}function q(t,e,a="ACCEPTED",n="REJECTED"){t.textContent=e?a:n,t.classList.remove("verdict-accept","verdict-reject","verdict-idle"),t.classList.add(e?"verdict-accept":"verdict-reject")}function v(t,e){t.textContent=e,t.classList.remove("verdict-accept","verdict-reject"),t.classList.add("verdict-idle")}function ot(){const t=c("timing-rows");t.textContent="";const e=ua();for(const a of e.rows){const n=document.createElement("tr"),r=document.createElement("td");r.textContent=a.label;const s=document.createElement("td");s.textContent=`${a.naiveMs.toFixed(3)} ms`;const i=document.createElement("td");i.textContent=`${a.constantMs.toFixed(3)} ms`,n.append(r,s,i),t.appendChild(n)}c("timing-summary").textContent=e.summary}const pa=`// HMAC = H(K' ⊕ opad || H(K' ⊕ ipad || message))
const ipad = new Uint8Array(blockSize);
const opad = new Uint8Array(blockSize);
for (let i = 0; i < blockSize; i++) {
  ipad[i] = normalizedKey[i] ^ 0x36;
  opad[i] = normalizedKey[i] ^ 0x5c;
}
const inner = await digest(hash, concat(ipad, message));
const outer = await digest(hash, concat(opad, inner));
return outer; // the HMAC tag`,ma=`// NIST SP 800-38B subkey derivation
const L = await aesEncryptBlock(key, new Uint8Array(16));
let K1 = leftShift(L);
if ((L[0] & 0x80) !== 0) K1[15] ^= 0x87;  // Rb
let K2 = leftShift(K1);
if ((K1[0] & 0x80) !== 0) K2[15] ^= 0x87;
// Last block: XOR with K1 if message is a whole multiple of 16,
// otherwise apply 10* padding and XOR with K2.`,ya=`// Two messages under the SAME one-time key leak r:
// tag1 = (m1 * r + s) mod 2^128
// tag2 = (m2 * r + s) mod 2^128
// tag1 - tag2 ≡ (m1 - m2) * r  → solve for r
for (let rGuess = 0n; rGuess <= 0xffffn; rGuess++) {
  const sGuess = (tag1 - m1*rGuess + MOD) % MOD;
  if ((m2*rGuess + sGuess) % MOD === tag2) {
    // forge any new message m3 with the recovered (r, s).
  }
}`,ba=`// GHASH is linear in GF(2^128):
//   T = C * H + L * H
// Two ciphertexts under the SAME nonce share the same H.
//   T1 ^ T2 = (C1 ^ C2) * H
//   H = (T1 ^ T2) * (C1 ^ C2)^(-1)
const deltaT = xor16(T1, T2);
const deltaC = xor16(C1, C2);
const H = gf128Mul(deltaT, gfInverse(deltaC));`,va=`// Attacker observes tag = SHA-256(secret || message)
// SHA-256 state IS the tag — attacker resumes from it.
const state = parseStateFromDigest(tagHex);
const glue = sha256Pad(secretLen + message.length);
const forgedMessage = concat(message, glue, append);
// Feed only the append + final padding into the resumed state.
const totalAfterAppend = secretLen + message.length + glue.length + append.length;
for (const block of blocks(append, sha256Pad(totalAfterAppend))) {
  compress(state, block);
}
return stateToDigestHex(state); // valid forged tag, secret never needed`,wa=`// VULNERABLE: leaks prefix-match length via early exit.
function naiveEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;     // ← early exit
  }
  return true;
}

// SAFE: constant time, branchless on data.
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}`,He=[{panelId:"p1",title:"1. HMAC — the safe default",body:"Start here. HMAC nests two hashes around the key so that knowing the tag tells you nothing about the internal hash state. This is what API request signing should use."},{panelId:"p5",title:"2. Why we need HMAC: length-extension",body:"Bare SHA-256(secret || message) leaks enough internal state through its tag that an attacker can forge tags for extended messages without the secret. Forge a tag, then verify it on the broken server."},{panelId:"p2",title:"3. CMAC — block-cipher MAC",body:"When AES is already in your stack, CMAC gives you a NIST-approved MAC built from a block cipher. Notice K1/K2 are derived from AES_K(0)."},{panelId:"p3",title:"4. Poly1305 — fast, one-time only",body:"A polynomial MAC. Reuse the one-time key across two messages and r can be solved in seconds; the attacker forges arbitrary tags afterwards."},{panelId:"p4",title:"5. GHASH — linear in GF(2^128)",body:"GHASH is what authenticates AES-GCM. It is linear in the field, so nonce reuse leaks the hash subkey H. This is the Forbidden Attack."},{panelId:"p6",title:"6. Timing attack — non-constant-time compare",body:"A naive byte-by-byte equality leaks prefix-match length. Watch a real byte-by-byte tag recovery driven entirely by that signal."}];function xa(t){t.innerHTML=`
    <div class="page" aria-label="MAC Race demo root">
      <a class="skip-link" href="#main-content" aria-label="Skip to main content">Skip to main content</a>
      <header class="hero" aria-label="Header section">
        <span class="chip chip-category" aria-label="Category chip">MAC</span>
        <button
          id="theme-toggle"
          class="theme-toggle"
          aria-label="Switch to light mode"
          style="position: absolute; top: 0; right: 0;"
        >🌙</button>
        <h1>MAC Race</h1>
        <p class="subtitle">Construction, misuse resistance, and real attack demonstrations for modern Message Authentication Codes.</p>
        <p class="chip-row" aria-label="Primitive chips">HMAC-SHA-256 · HMAC-SHA-512 · AES-CMAC · Poly1305 · GHASH</p>
      </header>

      <section class="tour" aria-label="Guided tour">
        <div class="tour-head">
          <div>
            <strong id="tour-title">Guided tour: start with HMAC →</strong>
            <p class="tour-body" id="tour-body">Click "Start tour" to walk through the panels in pedagogical order. Each step highlights one panel and explains what the lesson is.</p>
          </div>
          <div class="tour-controls">
            <button id="tour-start" aria-label="Start guided tour">Start tour</button>
            <button id="tour-prev" aria-label="Previous lesson" hidden>← Prev</button>
            <button id="tour-next" aria-label="Next lesson" hidden>Next →</button>
            <button id="tour-end" aria-label="End tour" hidden>End</button>
          </div>
        </div>
        <p class="tour-progress" id="tour-progress" hidden></p>
      </section>

      <main id="main-content" class="panel-grid" aria-label="MAC demo panels">

        <section class="panel" id="p1" aria-labelledby="p1-title">
          <div class="panel-head">
            <span class="lesson-badge">Lesson 1</span>
            <h2 id="p1-title">HMAC</h2>
            <span class="chip chip-ok" aria-label="Status RECOMMENDED DEFAULT">RECOMMENDED DEFAULT</span>
          </div>
          <label for="hmac-message">Message</label>
          <textarea id="hmac-message" aria-label="HMAC message input">transfer=42&to=bob</textarea>
          <label for="hmac-key">Key (text or hex)</label>
          <input id="hmac-key" aria-label="HMAC key input" value="super-secret-key" />
          <div class="button-row">
            <button id="hmac-run" aria-label="Compute HMAC results">Compute HMAC</button>
            <button id="hmac-step" class="secondary" aria-label="Step through HMAC stages">Step ▸</button>
            <button id="hmac-reveal" class="secondary" aria-label="Reveal all HMAC stages">Reveal all</button>
          </div>
          <div id="hmac-output" class="hex stepper" aria-label="HMAC output"></div>

          <div class="bitdiff-section">
            <p class="note"><strong>Avalanche:</strong> flip one bit of the message or one bit of the key — watch ~50% of output bits change.</p>
            <div id="hmac-bitdiff-msg" class="bitdiff-block"></div>
            <div id="hmac-bitdiff-key" class="bitdiff-block"></div>
          </div>

          <div class="verifier" aria-label="HMAC server verifier">
            <h3>Server verifies</h3>
            <label for="hmac-verify-tag">Candidate tag (hex)</label>
            <input id="hmac-verify-tag" aria-label="HMAC candidate tag" />
            <div class="button-row">
              <button id="hmac-verify" aria-label="Verify HMAC tag">Verify on server</button>
              <span id="hmac-verdict" class="verdict verdict-idle">awaiting input</span>
            </div>
          </div>

          <p class="note">FIPS 198-1: HMAC uses nested hashing with ipad/opad, so length extension against bare SHA-256 does not apply.</p>

          <details class="source-toggle"><summary>Show implementation</summary><pre class="src">${te(pa)}</pre></details>
        </section>

        <section class="panel" id="p2" aria-labelledby="p2-title">
          <div class="panel-head">
            <span class="lesson-badge">Lesson 3</span>
            <h2 id="p2-title">CMAC</h2>
            <span class="chip chip-ok" aria-label="Status RECOMMENDED for FIPS contexts">RECOMMENDED (FIPS contexts)</span>
          </div>
          <label for="cmac-message">Message</label>
          <textarea id="cmac-message" aria-label="CMAC message input">audit-log-entry</textarea>
          <label for="cmac-key">AES-256 key (64 hex or passphrase)</label>
          <input id="cmac-key" aria-label="CMAC key input" value="fips-demo-key" />
          <div class="button-row">
            <button id="cmac-run" aria-label="Compute CMAC">Compute CMAC</button>
            <button id="cmac-step" class="secondary" aria-label="Step through CMAC stages">Step ▸</button>
            <button id="cmac-reveal" class="secondary" aria-label="Reveal all CMAC stages">Reveal all</button>
          </div>
          <div id="cmac-output" class="hex stepper" aria-label="CMAC output"></div>

          <div class="verifier" aria-label="CMAC server verifier">
            <h3>Server verifies</h3>
            <label for="cmac-verify-tag">Candidate tag (hex)</label>
            <input id="cmac-verify-tag" aria-label="CMAC candidate tag" />
            <div class="button-row">
              <button id="cmac-verify" aria-label="Verify CMAC tag">Verify on server</button>
              <span id="cmac-verdict" class="verdict verdict-idle">awaiting input</span>
            </div>
          </div>

          <p class="note">NIST SP 800-38B: derives K1/K2 from AES_K(0^128), applies 10* padding, and XORs final block before last encryption.</p>

          <details class="source-toggle"><summary>Show implementation</summary><pre class="src">${te(ma)}</pre></details>
        </section>

        <section class="panel" id="p3" aria-labelledby="p3-title">
          <div class="panel-head">
            <span class="lesson-badge">Lesson 4</span>
            <h2 id="p3-title">Poly1305</h2>
            <span class="chip chip-ok" aria-label="Status RECOMMENDED with ChaCha20">RECOMMENDED (always with ChaCha20)</span>
          </div>

          <label for="poly-message">Message</label>
          <textarea id="poly-message" aria-label="Poly1305 message input">Cryptographic Forum Research Group</textarea>
          <div class="button-row">
            <button id="poly-run" aria-label="Compute Poly1305 tag">Compute tag</button>
          </div>
          <pre id="poly-output" class="hex" aria-label="Poly1305 output"></pre>

          <div class="attack-pane" aria-label="Poly1305 one-time key reuse attack">
            <h3>You are the attacker</h3>
            <p class="note">A buggy server reused the <em>same</em> one-time key for two invoice messages. Recover <code>r</code> and forge a new invoice.</p>
            <div class="button-row">
              <button id="poly-attack" aria-label="Run Poly1305 key reuse attack">Run reuse attack →</button>
            </div>
            <pre id="poly-attack-output" class="hex" aria-label="Poly1305 attack output"></pre>
          </div>

          <div class="verifier" aria-label="Poly1305 server verifier">
            <h3>Server verifies</h3>
            <p class="note">Submit the forged tag from the attack against the original key. Both messages were authenticated with that key — so the server <em>will</em> accept your forgery.</p>
            <div class="button-row">
              <button id="poly-verify" aria-label="Submit forged tag to Poly1305 server">Submit forged tag</button>
              <span id="poly-verdict" class="verdict verdict-idle">awaiting attack</span>
            </div>
          </div>

          <div class="callout-cve" aria-label="Incident callout">
            <strong>📜 RFC 8439 warns explicitly:</strong> "The key MUST be unpredictable for each invocation." Implementations that reused Poly1305 keys (early Wireguard / experimental QUIC ports, 2015–2018 era code) had to be patched specifically for this property.
          </div>

          <p class="note">RFC 8439: Poly1305 must use a unique one-time key per message, usually derived by ChaCha20 with a unique nonce.</p>

          <details class="source-toggle"><summary>Show attack implementation</summary><pre class="src">${te(ya)}</pre></details>
        </section>

        <section class="panel" id="p4" aria-labelledby="p4-title">
          <div class="panel-head">
            <span class="lesson-badge">Lesson 5</span>
            <h2 id="p4-title">GHASH</h2>
            <span class="chip chip-warn" aria-label="Status secure only with nonce discipline">SECURE only with nonce discipline</span>
          </div>
          <label for="ghash-ciphertext">Ciphertext (hex)</label>
          <textarea id="ghash-ciphertext" aria-label="GHASH ciphertext hex input">0388dace60b6a392f328c2b971b2fe78</textarea>
          <div class="button-row">
            <button id="ghash-run" aria-label="Compute GHASH">Compute GHASH</button>
          </div>
          <pre id="ghash-output" class="hex" aria-label="GHASH output"></pre>

          <div class="attack-pane" aria-label="GHASH nonce reuse attack">
            <h3>You are the attacker</h3>
            <p class="note">Two ciphertexts encrypted under the <em>same</em> AES-GCM nonce share the same hash subkey H. With a single delta you can solve for H and forge tags for any other ciphertext.</p>
            <div class="button-row">
              <button id="ghash-attack" aria-label="Run GHASH nonce reuse attack">Run nonce reuse attack →</button>
            </div>
            <pre id="ghash-attack-output" class="hex" aria-label="GHASH attack output"></pre>
          </div>

          <div class="verifier" aria-label="GHASH server verifier">
            <h3>Server verifies</h3>
            <p class="note">After the nonce-reuse attack recovers H, the attacker can issue a forged tag for any ciphertext. The demo's local constant-time check (shown above) is the same operation a real GCM endpoint runs.</p>
            <div class="button-row">
              <button id="ghash-verify" aria-label="Submit forged GHASH tag">Submit forged tag</button>
              <span id="ghash-verdict" class="verdict verdict-idle">awaiting attack</span>
            </div>
          </div>

          <div class="callout-cve" aria-label="Incident callout">
            <strong>🔓 Forbidden Attack (Böck, Zauner, Devlin — 2016):</strong> a scan of the public web found 184 HTTPS servers and IoT devices reusing GCM nonces. Researchers extracted authentication keys and demonstrated full message forgery over real TLS.
          </div>

          <p class="note">NIST SP 800-38D: GHASH is linear in GF(2^128). Reusing a GCM nonce is catastrophic.</p>

          <details class="source-toggle"><summary>Show attack implementation</summary><pre class="src">${te(ba)}</pre></details>
        </section>

        <section class="panel panel-wide" id="p5" aria-labelledby="p5-title">
          <div class="panel-head">
            <span class="lesson-badge">Lesson 2</span>
            <h2 id="p5-title">Length Extension Attack</h2>
            <span class="chip chip-bad" aria-label="Status bare SHA-256 as MAC avoid">bare SHA-256 as MAC = AVOID</span>
          </div>

          <div class="capture-pane">
            <h3>1. Captured request (from the wire)</h3>
            <p class="note">The attacker observed an authenticated message and its tag in transit. They do not know the secret.</p>
            <label for="le-message">Original message</label>
            <input id="le-message" aria-label="Original message for length extension" value="comment=10&uid=7" />
            <div class="button-row">
              <button id="le-capture" aria-label="Capture original request">Capture original</button>
              <button id="le-reset-secret" class="secondary" aria-label="Rotate the secret">Rotate secret</button>
            </div>
            <div class="side-by-side">
              <div class="side broken">
                <div class="side-label"><span class="badge-bad">BROKEN</span> Server uses <code>SHA-256(secret &#124;&#124; msg)</code></div>
                <pre id="le-raw-tag" class="hex">(click "Capture original")</pre>
              </div>
              <div class="side safe">
                <div class="side-label"><span class="badge-ok">SAFE</span> Server uses <code>HMAC-SHA-256(secret, msg)</code></div>
                <pre id="le-hmac-tag" class="hex">(click "Capture original")</pre>
              </div>
            </div>
          </div>

          <div class="attack-pane">
            <h3>2. Forge a tag without the secret</h3>
            <p class="note">Length extension lets the attacker compute a valid tag for <code>message &#124;&#124; glue &#124;&#124; append</code> from the leaked tag — but only if they guess the secret length. The actual length is hidden somewhere in <strong>${ae[0]}..${ae[1]} bytes</strong>.</p>
            <label for="le-append">Attacker-appended data</label>
            <input id="le-append" aria-label="Appended attacker data" value="&admin=true" />
            <label for="le-guess">Guessed secret length: <span id="le-guess-value">16</span></label>
            <input id="le-guess" type="range" min="${ae[0]}" max="${ae[1]}" step="1" value="16" aria-label="Guessed secret length slider" />
            <div class="button-row">
              <button id="le-forge" aria-label="Forge a length-extended tag">Forge tag</button>
            </div>
            <pre id="le-forge-output" class="hex">(capture, then forge)</pre>
          </div>

          <div class="verifier">
            <h3>3. Submit the forgeries to both servers</h3>
            <div class="side-by-side">
              <div class="side broken">
                <div class="side-label"><span class="badge-bad">BROKEN server</span></div>
                <div class="button-row">
                  <button id="le-verify-raw" aria-label="Verify forged tag on bare SHA-256 server">Submit to bare-SHA-256 server</button>
                  <span id="le-verdict-raw" class="verdict verdict-idle">awaiting forge</span>
                </div>
              </div>
              <div class="side safe">
                <div class="side-label"><span class="badge-ok">SAFE server</span></div>
                <div class="button-row">
                  <button id="le-verify-hmac" aria-label="Verify forged tag on HMAC server">Submit to HMAC server</button>
                  <span id="le-verdict-hmac" class="verdict verdict-idle">awaiting forge</span>
                </div>
              </div>
            </div>
            <p class="note" id="le-summary"></p>
          </div>

          <div class="callout-cve">
            <strong>🔓 Flickr API (2009):</strong> Flickr's signed request scheme used <code>md5(secret &#124;&#124; query)</code>. Researchers Duong and Rizzo (the Lucky 13 / BEAST team) demonstrated tag forgery via length extension and could call arbitrary signed API methods. Fixed by switching to HMAC.
          </div>

          <details class="source-toggle"><summary>Show attack implementation</summary><pre class="src">${te(va)}</pre></details>
        </section>

        <section class="panel panel-wide" id="p6" aria-labelledby="p6-title">
          <div class="panel-head">
            <span class="lesson-badge">Lesson 6</span>
            <h2 id="p6-title">MAC Comparison + Timing Attack</h2>
          </div>
          <div class="table-wrap" aria-label="MAC comparison table">
            <table>
              <caption class="sr-only">MAC primitive comparison: construction, key size, tag size, PQ resistance, and use case</caption>
              <thead><tr><th>Primitive</th><th>Construction</th><th>Key</th><th>Tag</th><th>PQ</th><th>Use case</th></tr></thead>
              <tbody>
                <tr><td>HMAC-SHA-256</td><td>Hash (Merkle-Damgard wrapped)</td><td>Any secret</td><td>256b</td><td>No</td><td>General API auth</td></tr>
                <tr><td>HMAC-SHA-512</td><td>Hash</td><td>Any secret</td><td>512b</td><td>No</td><td>Long-term integrity tokens</td></tr>
                <tr><td>AES-256-CMAC</td><td>Block cipher</td><td>256b AES</td><td>128b</td><td>No</td><td>FIPS/NIST contexts</td></tr>
                <tr><td>Poly1305</td><td>Polynomial mod 2^130-5</td><td>256b one-time</td><td>128b</td><td>No</td><td>ChaCha20-Poly1305</td></tr>
                <tr><td>GHASH</td><td>Polynomial mod x^128+x^7+x^2+x+1</td><td>128b subkey H</td><td>128b</td><td>No</td><td>AES-GCM internals</td></tr>
              </tbody>
            </table>
          </div>

          <h3>Timing differential (naive vs constant-time compare)</h3>
          <div class="button-row">
            <button id="timing-run" aria-label="Measure timing attack differences">Measure timing</button>
          </div>
          <div class="table-wrap" aria-label="Timing attack measurements">
            <table>
              <caption class="sr-only">Timing attack demonstration: naive versus constant-time MAC comparison</caption>
              <thead><tr><th>Case</th><th>Naive compare</th><th>Constant-time compare</th></tr></thead>
              <tbody id="timing-rows"></tbody>
            </table>
          </div>
          <p id="timing-summary" class="note"></p>

          <div class="attack-pane">
            <h3>Real byte-by-byte tag recovery</h3>
            <p class="note">A simulated server holds a random 16-byte tag and compares submitted candidates with <code>naiveEqual</code>. The attacker submits 256 candidates per byte position and keeps whichever produced the longest prefix-match time — recovering the entire tag without ever knowing the secret.</p>
            <div class="button-row">
              <label for="recovery-bytes">Bytes to recover:</label>
              <input id="recovery-bytes" type="number" min="1" max="16" value="8" aria-label="Number of bytes to recover" style="width: 5rem; min-height: 2rem;" />
              <button id="recovery-run" aria-label="Run byte-by-byte recovery attack">Start recovery →</button>
            </div>
            <div id="recovery-progress" class="recovery-progress" aria-live="polite">
              <div class="recovery-bar"><div id="recovery-bar-fill" class="recovery-bar-fill"></div></div>
              <p id="recovery-status" class="note">idle</p>
              <pre id="recovery-output" class="hex"></pre>
            </div>
          </div>

          <div class="callout-cve">
            <strong>🔓 Lucky 13 (AlFardan & Paterson — 2013):</strong> TLS 1.0–1.2 record MAC verification had measurable timing variation tied to padding length. Practical key-byte recovery against CBC-mode TLS, demonstrated against OpenSSL, NSS, and GnuTLS.<br/>
            <strong>🔓 Keyczar (Google) 2009, Java's <code>MessageDigest.isEqual</code> pre-Java 6u17:</strong> shipped non-constant-time MAC comparison; both fixed after public disclosure.
          </div>

          <details class="source-toggle"><summary>Show implementation</summary><pre class="src">${te(wa)}</pre></details>
        </section>
      </main>

      <section class="why" aria-label="Why this matters">
        <h2>Why this matters</h2>
        <p>MAC failure is one of the most common causes of production cryptographic vulnerabilities. Length extension and timing attacks have repeatedly broken real systems.</p>
        <p class="links" aria-label="Cross links">
          <a href="https://systemslibrarian.github.io/crypto-lab/" target="_blank" rel="noreferrer">crypto-lab</a>
          <a href="https://systemslibrarian.github.io/crypto-lab-aes-modes/" target="_blank" rel="noreferrer">crypto-lab-aes-modes</a>
          <a href="https://systemslibrarian.github.io/crypto-lab-shadow-vault/" target="_blank" rel="noreferrer">crypto-lab-shadow-vault</a>
          <a href="https://systemslibrarian.github.io/crypto-lab-babel-hash/" target="_blank" rel="noreferrer">crypto-lab-babel-hash</a>
          <a href="https://systemslibrarian.github.io/crypto-compare/#mac" target="_blank" rel="noreferrer">crypto-compare MAC</a>
        </p>
      </section>

      <footer class="footer" aria-label="Footer">
        <a class="github-badge" href="https://github.com/systemslibrarian/crypto-lab-mac-race" target="_blank" rel="noreferrer" aria-label="GitHub repository link">GitHub</a>
        <p>So whether you eat or drink or whatever you do, do it all for the glory of God. - 1 Corinthians 10:31</p>
      </footer>
      <div id="aria-live" class="sr-only" aria-live="polite" role="status"></div>
    </div>
  `,Aa(),Ha(),ka(),Ca(),Sa(),Ea(),Ma(),ot()}function te(t){return t.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;")}function Aa(){let t=null;const e=async a=>{const n=c("hmac-message").value,r=c("hmac-key").value,s=await re(n,r,"SHA-256"),i=await re(n,r,"SHA-512"),o=await It(n,r),l=[`Step 1 — normalized key (padded to block size):  ${ce(s.visual.normalizedKeyHex)}`,`Step 2 — inner pad (key ⊕ 0x36):                 ${ce(s.visual.ipadHex)}`,`Step 3 — outer pad (key ⊕ 0x5c):                 ${ce(s.visual.opadHex)}`,`Step 4 — inner = SHA-256(ipad ∥ message):        ${s.visual.innerHashHex}`,`Step 5 — outer = SHA-256(opad ∥ inner) = TAG:    ${s.visual.outerHashHex}`,`HMAC-SHA-256 tag:  ${s.macHex}`,`HMAC-SHA-512 tag:  ${i.macHex}`];t=st(c("hmac-output"),l),a&&t.revealAll(),ze(c("hmac-bitdiff-msg"),o.original,o.flippedMessage,"Flip 1 bit of the message"),ze(c("hmac-bitdiff-key"),o.original,o.flippedKey,"Flip 1 bit of the key"),c("hmac-verify-tag").value=s.macHex,v(c("hmac-verdict"),"tag ready — click Verify")};c("hmac-run").addEventListener("click",async()=>{try{await e(!0),m("HMAC computed successfully.")}catch(a){m(`HMAC error: ${a.message}`,!0)}}),c("hmac-step").addEventListener("click",async()=>{try{t||await e(!1);const a=t.step();m(a?"Step advanced.":"All HMAC stages revealed.")}catch(a){m(`HMAC error: ${a.message}`,!0)}}),c("hmac-reveal").addEventListener("click",async()=>{try{t||await e(!1),t.revealAll()}catch(a){m(`HMAC error: ${a.message}`,!0)}}),c("hmac-verify").addEventListener("click",async()=>{const a=c("hmac-verdict");try{const n=c("hmac-message").value,r=c("hmac-key").value,s=c("hmac-verify-tag").value.trim(),i=await Rt(n,r,"SHA-256",s);q(a,i)}catch{q(a,!1)}})}function Ha(){let t=null;const e=async a=>{const n=c("cmac-message").value,r=c("cmac-key").value,s=await We(n,r),i=[`Step 1 — AES-256 key (normalized):                 ${ce(s.details.keyHex)}`,`Step 2 — L = AES_K(0^128) → K1 (after << 1 + Rb):  ${s.details.k1Hex}`,`Step 3 —                              K2:          ${s.details.k2Hex}`,`Step 4 — Padded last block (10* if needed):        ${s.details.paddedLastBlockHex}`,`Step 5 — Final block XOR with K1/K2:               ${s.details.finalXorBlockHex}`,`Step 6 — CBC chain so far:                         ${s.details.chainingHex.join(" → ")||"(single-block message — chain is empty)"}`,`Step 7 — Final encrypt = TAG:                      ${s.tagHex}`];t=st(c("cmac-output"),i),a&&t.revealAll(),c("cmac-verify-tag").value=s.tagHex,v(c("cmac-verdict"),"tag ready — click Verify")};c("cmac-run").addEventListener("click",async()=>{try{await e(!0),m("CMAC computed successfully.")}catch(a){m(`CMAC error: ${a.message}`,!0)}}),c("cmac-step").addEventListener("click",async()=>{try{t||await e(!1);const a=t.step();m(a?"Step advanced.":"All CMAC stages revealed.")}catch(a){m(`CMAC error: ${a.message}`,!0)}}),c("cmac-reveal").addEventListener("click",async()=>{try{t||await e(!1),t.revealAll()}catch(a){m(`CMAC error: ${a.message}`,!0)}}),c("cmac-verify").addEventListener("click",async()=>{const a=c("cmac-verdict");try{const n=c("cmac-message").value,r=c("cmac-key").value,s=c("cmac-verify-tag").value.trim(),i=await ht(n,r,s);q(a,i)}catch{q(a,!1)}})}function ka(){let t=null;c("poly-run").addEventListener("click",()=>{try{const e=c("poly-message").value,a=ca(e);c("poly-output").textContent=`Poly1305 tag: ${a.tagHex}
One-time key: ${a.keyHex}
(Tag computed mod 2^130 − 5, then reduced mod 2^128 + s.)`,m("Poly1305 tag computed.")}catch(e){m(`Poly1305 error: ${e.message}`,!0)}}),c("poly-attack").addEventListener("click",()=>{try{const e=la();t=e,c("poly-attack-output").textContent=`Observed:
  ${e.msg1}  →  tag ${e.tag1Hex}
  ${e.msg2}  →  tag ${e.tag2Hex}

Solved weak r = 0x${e.recoveredRHex}
Forged ${e.msg3}  →  tag ${e.forgedTagHex}
Attacker's local check: forgery ${e.validForgery?"valid":"invalid"}.`,v(c("poly-verdict"),"forged tag ready — submit it"),m("Poly1305 key reuse attack succeeded.")}catch(e){m(`Poly1305 attack error: ${e.message}`,!0)}}),c("poly-verify").addEventListener("click",()=>{if(!t){v(c("poly-verdict"),"run the attack first");return}q(c("poly-verdict"),t.validForgery)})}function Ca(){let t=null;c("ghash-run").addEventListener("click",async()=>{try{const e=c("ghash-ciphertext").value.trim(),a=await Ct(e);c("ghash-output").textContent=`H = E_K(0^128): ${a.hHex}
GHASH output:   ${a.yHex}
Per-block:      ${a.steps.join(" → ")}`,m("GHASH computed.")}catch(e){m(`GHASH error: ${e.message}`,!0)}}),c("ghash-attack").addEventListener("click",()=>{try{const e=Mt();t=e,c("ghash-attack-output").textContent=`Δ ciphertext: ${e.deltaCHex}
Δ tag:        ${e.deltaTHex}
Recovered H = ΔT · (ΔC)⁻¹ = ${e.recoveredHHex}
Forgery against a new ciphertext ${e.forgedValid?"VALID":"invalid"}.

`+e.note,v(c("ghash-verdict"),"forged — submit it"),m("GHASH nonce reuse attack succeeded.")}catch(e){m(`GHASH attack error: ${e.message}`,!0)}}),c("ghash-verify").addEventListener("click",()=>{if(!t){v(c("ghash-verdict"),"run the attack first");return}q(c("ghash-verdict"),t.forgedValid)})}function Sa(){let t=null,e=null;const a=c("le-guess"),n=c("le-guess-value");a.addEventListener("input",()=>{n.textContent=a.value}),c("le-capture").addEventListener("click",async()=>{try{const o=c("le-message").value,l=await Qt(o);t={message:o,...l},c("le-raw-tag").textContent=l.rawMacHex,c("le-hmac-tag").textContent=l.hmacMacHex,v(c("le-verdict-raw"),"awaiting forge"),v(c("le-verdict-hmac"),"awaiting forge"),c("le-forge-output").textContent="(now pick a guessed length and forge)",c("le-summary").textContent=`Secret length is hidden somewhere in ${ae[0]}..${ae[1]} bytes. Guess and forge.`,m("Captured original request.")}catch(o){m(`Capture error: ${o.message}`,!0)}}),c("le-reset-secret").addEventListener("click",()=>{const o=Wt();t=null,e=null,c("le-raw-tag").textContent="(rotated — capture again)",c("le-hmac-tag").textContent="(rotated — capture again)",c("le-forge-output").textContent="(secret rotated; capture, then forge)",v(c("le-verdict-raw"),"rotated — recapture"),v(c("le-verdict-hmac"),"rotated — recapture"),m(`Secret rotated (new length ${o} bytes, hidden).`)}),c("le-forge").addEventListener("click",async()=>{if(!t){m("Capture the original request first.",!0);return}try{const o=c("le-append").value,l=Number(a.value),u=await Yt(t.message,t.rawMacHex,t.hmacMacHex,o,l);e={messageBytes:Le(u.forgedMessageHex),rawTagHex:u.forgedRawTagHex,hmacAttemptHex:u.forgedHmacTagAttemptHex},c("le-forge-output").textContent=`Guessed secret length: ${u.guessedSecretLength}
Forged message (visible): ${u.forgedMessageVisible}
Forged message (hex):     ${ce(u.forgedMessageHex,200)}
Forged tag (broken construction):       ${u.forgedRawTagHex}
Forged tag (HMAC attempt — won't work): ${u.forgedHmacTagAttemptHex}
`,v(c("le-verdict-raw"),"forged — submit it"),v(c("le-verdict-hmac"),"forged — submit it"),m(`Forge complete with guessed length ${u.guessedSecretLength}.`)}catch(o){m(`Forge error: ${o.message}`,!0)}}),c("le-verify-raw").addEventListener("click",async()=>{if(!e){v(c("le-verdict-raw"),"forge first");return}const o=await tt(e.messageBytes,e.rawTagHex);q(c("le-verdict-raw"),o),i(o,null)}),c("le-verify-hmac").addEventListener("click",async()=>{if(!e){v(c("le-verdict-hmac"),"forge first");return}const o=await at(e.messageBytes,e.hmacAttemptHex);q(c("le-verdict-hmac"),o),i(null,o)});let r=null,s=null;function i(o,l){o!==null&&(r=o),l!==null&&(s=l);const u=Xt(),d=Number(a.value),f=[];r===!0&&f.push(`✅ BROKEN server accepted the forgery (you guessed the secret length: ${d} = ${u}).`),r===!1&&f.push(`❌ BROKEN server rejected — guess ${d} did not match actual length ${u}. Try a different slider value.`),s===!0&&f.push("⚠️ SAFE server also accepted? That shouldn't happen — please report."),s===!1&&f.push("🛡️ SAFE server rejected — HMAC is immune to this attack technique."),c("le-summary").textContent=f.join(" ")}}function Ea(){c("timing-run").addEventListener("click",()=>{ot(),m("Timing measurements updated.")}),c("recovery-run").addEventListener("click",async()=>{const t=c("recovery-bytes"),e=Math.max(1,Math.min(16,Number(t.value)||8)),a=c("recovery-status"),n=c("recovery-output"),r=c("recovery-bar-fill");n.textContent="",a.textContent="starting…",r.style.width="0%";const s=await ha(16,o=>{const l=(o.byteIndex+1)/e*100;r.style.width=`${l}%`,a.textContent=`Recovered byte ${o.byteIndex+1}/${e} = 0x${o.byteValue.toString(16).padStart(2,"0")} (${o.oracleQueries} oracle queries so far)`,n.textContent=`Recovered prefix: ${o.recoveredHex}`},e),i=s.recoveredTagHex+(s.recoveredTagHex.length<32?"..".repeat((32-s.recoveredTagHex.length)/2):"");n.textContent=`Recovered: ${i}
True tag:  ${s.trueTagHex}
Match for first ${s.bytesRecovered} bytes: ${s.success?"✅ YES":"❌ NO"}
Total oracle queries: ${s.oracleQueries}  (≈ 256 per byte)`,a.textContent=s.success?`Recovered ${s.bytesRecovered} bytes via prefix-match timing leak.`:"Recovery diverged from true tag.",m("Byte-by-byte recovery complete.")})}function Ma(){let t=-1;const e=c("tour-title"),a=c("tour-body"),n=c("tour-progress"),r=c("tour-start"),s=c("tour-prev"),i=c("tour-next"),o=c("tour-end");function l(d){if(document.querySelectorAll(".panel").forEach(y=>y.classList.remove("panel-active")),d<0)return;const f=He[d],h=document.getElementById(f.panelId);h&&(h.classList.add("panel-active"),h.scrollIntoView({behavior:"smooth",block:"start"})),e.textContent=f.title,a.textContent=f.body,n.hidden=!1,n.textContent=`Lesson ${d+1} of ${He.length}`}function u(d){r.hidden=d,s.hidden=!d,i.hidden=!d,o.hidden=!d}r.addEventListener("click",()=>{t=0,u(!0),l(t)}),s.addEventListener("click",()=>{t>0&&(t-=1),l(t)}),i.addEventListener("click",()=>{if(t<He.length-1)t+=1;else{u(!1),t=-1,document.querySelectorAll(".panel").forEach(d=>d.classList.remove("panel-active")),e.textContent="Tour complete — explore freely",a.textContent="You can restart the tour any time.",n.hidden=!0;return}l(t)}),o.addEventListener("click",()=>{u(!1),t=-1,document.querySelectorAll(".panel").forEach(d=>d.classList.remove("panel-active")),e.textContent="Guided tour: start with HMAC →",a.textContent='Click "Start tour" to walk through the panels in pedagogical order.',n.hidden=!0})}function Ta(){const t=document.documentElement,e=document.querySelector("#theme-toggle");if(!e)return;const a=r=>{t.dataset.theme=r,e.textContent=r==="dark"?"🌙":"☀️",e.setAttribute("aria-label",r==="dark"?"Switch to light mode":"Switch to dark mode")},n=t.dataset.theme==="light"?"light":"dark";a(n),e.addEventListener("click",()=>{const r=t.dataset.theme==="light"?"dark":"light";a(r),localStorage.setItem("theme",r)})}async function $a(){const t=await Promise.all([Pt(),gt(),Promise.resolve(da()),Promise.resolve(Tt()),ea(),Promise.resolve(ga())]);t.some(e=>!e)&&console.warn("One or more cryptographic self-tests failed.",t)}const it=document.querySelector("#app");if(!it)throw new Error("Missing #app container");xa(it);Ta();$a();
