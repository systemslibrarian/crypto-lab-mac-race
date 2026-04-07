(function(){const e=document.createElement("link").relList;if(e&&e.supports&&e.supports("modulepreload"))return;for(const a of document.querySelectorAll('link[rel="modulepreload"]'))r(a);new MutationObserver(a=>{for(const o of a)if(o.type==="childList")for(const s of o.addedNodes)s.tagName==="LINK"&&s.rel==="modulepreload"&&r(s)}).observe(document,{childList:!0,subtree:!0});function n(a){const o={};return a.integrity&&(o.integrity=a.integrity),a.referrerPolicy&&(o.referrerPolicy=a.referrerPolicy),a.crossOrigin==="use-credentials"?o.credentials="include":a.crossOrigin==="anonymous"?o.credentials="omit":o.credentials="same-origin",o}function r(a){if(a.ep)return;a.ep=!0;const o=n(a);fetch(a.href,o)}})();const Re=new TextEncoder,b=16,Se=135;function N(t){return Array.from(t,e=>e.toString(16).padStart(2,"0")).join("")}function de(t){const e=t.trim().toLowerCase();if(!/^[0-9a-f]*$/.test(e)||e.length%2!==0)throw new Error("Expected an even-length hex string");const n=new Uint8Array(e.length/2);for(let r=0;r<n.length;r+=1)n[r]=Number.parseInt(e.slice(r*2,r*2+2),16);return n}function ze(t){return/^[0-9a-fA-F]+$/.test(t)&&t.length%2===0}async function je(t){const e=t.trim();if(!e)throw new Error("CMAC key is required");if(ze(e)&&e.length===64)return de(e);const n=await crypto.subtle.digest("SHA-256",Re.encode(t));return new Uint8Array(n)}function ce(t,e){const n=new Uint8Array(b);for(let r=0;r<b;r+=1)n[r]=t[r]^e[r];return n}function Me(t){const e=new Uint8Array(b);let n=0;for(let r=b-1;r>=0;r-=1){const a=t[r];e[r]=a<<1&255|n,n=(a&128)>>>7}return e}async function he(t,e){const n=await crypto.subtle.importKey("raw",t,{name:"AES-CBC"},!1,["encrypt"]),r=new Uint8Array(b),a=await crypto.subtle.encrypt({name:"AES-CBC",iv:r},n,e);return new Uint8Array(a).slice(0,b)}async function Xe(t){const e=new Uint8Array(b),n=await he(t,e);let r=Me(n);n[0]&128&&(r[b-1]^=Se);let a=Me(r);return r[0]&128&&(a[b-1]^=Se),{k1:r,k2:a}}function We(t){if(t.length===0)return[new Uint8Array(b)];const e=[];for(let n=0;n<t.length;n+=b)e.push(t.slice(n,n+b));return e}function Ye(t){const e=new Uint8Array(b);return e.set(t,0),e[t.length]=128,e}async function Qe(t,e){return Ne(Re.encode(t),e)}async function Ne(t,e){const n=await je(e),{k1:r,k2:a}=await Xe(n),o=We(t),s=o.length-1,i=t.length!==0&&t.length%b===0,c=o[s],d=i?c:Ye(c),f=ce(d,i?r:a);let p=new Uint8Array(b);const u=[];for(let g=0;g<s;g+=1)p=await he(n,ce(p,o[g])),u.push(N(p));const m=await he(n,ce(p,f));return{tagHex:N(m),details:{keyHex:N(n),k1Hex:N(r),k2Hex:N(a),paddedLastBlockHex:N(d),finalXorBlockHex:N(f),chainingHex:u}}}async function Ze(){const t="603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",e="6bc1bee22e409f96e93d7e117393172a",n="28a7023f452e8f82bd4bf28d8c37c35c",r=de(t),a=await Ne(de(e),t);return N(r)===a.details.keyHex&&a.tagHex===n}/*! noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com) */function Oe(t){return t instanceof Uint8Array||ArrayBuffer.isView(t)&&t.constructor.name==="Uint8Array"}function re(t,...e){if(!Oe(t))throw new Error("Uint8Array expected");if(e.length>0&&!e.includes(t.length))throw new Error("Uint8Array expected of length "+e+", got length="+t.length)}function Ee(t,e=!0){if(t.destroyed)throw new Error("Hash instance has been destroyed");if(e&&t.finished)throw new Error("Hash#digest() has already been called")}function Je(t,e){re(t);const n=e.outputLen;if(t.length<n)throw new Error("digestInto() expects output buffer of length at least "+n)}function Ue(...t){for(let e=0;e<t.length;e++)t[e].fill(0)}const Ke=typeof Uint8Array.from([]).toHex=="function"&&typeof Uint8Array.fromHex=="function",et=Array.from({length:256},(t,e)=>e.toString(16).padStart(2,"0"));function P(t){if(re(t),Ke)return t.toHex();let e="";for(let n=0;n<t.length;n++)e+=et[t[n]];return e}const D={_0:48,_9:57,A:65,F:70,a:97,f:102};function $e(t){if(t>=D._0&&t<=D._9)return t-D._0;if(t>=D.A&&t<=D.F)return t-(D.A-10);if(t>=D.a&&t<=D.f)return t-(D.a-10)}function K(t){if(typeof t!="string")throw new Error("hex string expected, got "+typeof t);if(Ke)return Uint8Array.fromHex(t);const e=t.length,n=e/2;if(e%2)throw new Error("hex string expected, got unpadded hex of length "+e);const r=new Uint8Array(n);for(let a=0,o=0;a<n;a++,o+=2){const s=$e(t.charCodeAt(o)),i=$e(t.charCodeAt(o+1));if(s===void 0||i===void 0){const c=t[o]+t[o+1];throw new Error('hex string expected, got non-hex character "'+c+'" at index '+o)}r[a]=s*16+i}return r}function tt(t){if(typeof t!="string")throw new Error("string expected");return new Uint8Array(new TextEncoder().encode(t))}function pe(t){if(typeof t=="string")t=tt(t);else if(Oe(t))t=nt(t);else throw new Error("Uint8Array expected, got "+typeof t);return t}function nt(t){return Uint8Array.from(t)}const x=16,rt=0xe1000000000000000000000000000000n,at=(1n<<128n)-1n;function ae(t,e){const n=new Uint8Array(x);for(let r=0;r<x;r+=1)n[r]=t[r]^e[r];return n}function Be(t){let e=0n;for(const n of t)e=(e<<8n)+BigInt(n);return e}function ot(t){const e=new Uint8Array(x);let n=t&at;for(let r=x-1;r>=0;r-=1)e[r]=Number(n&0xffn),n>>=8n;return e}function L(t,e){let n=Be(t),r=Be(e),a=0n;for(let o=0;o<128;o+=1){(n&1n<<BigInt(127-o))!==0n&&(a^=r);const s=r&1n;r>>=1n,s&&(r^=rt)}return ot(a)}function st(t,e){const n=new Uint8Array(x),r=BigInt(t)*8n,a=BigInt(e)*8n;for(let o=0;o<8;o+=1)n[7-o]=Number(r>>BigInt(o*8)&0xffn),n[15-o]=Number(a>>BigInt(o*8)&0xffn);return n}function it(t){const e=[];for(let n=0;n<t.length;n+=x){const r=new Uint8Array(x);r.set(t.slice(n,n+x),0),e.push(r)}return t.length===0&&e.push(new Uint8Array(x)),e}async function ct(t,e){const n=await crypto.subtle.importKey("raw",t,{name:"AES-CBC"},!1,["encrypt"]),r=new Uint8Array(x),a=await crypto.subtle.encrypt({name:"AES-CBC",iv:r},n,e);return new Uint8Array(a).slice(0,x)}async function lt(t,e){const n=K(t),r=crypto.getRandomValues(new Uint8Array(16)),a=await ct(r,new Uint8Array(x));let o=new Uint8Array(x);const s=[];for(const c of it(n))o=L(ae(o,c),a),s.push(P(o));const i=st(0,n.length);return o=L(ae(o,i),a),s.push(P(o)),{hHex:P(a),yHex:P(o),steps:s}}function ft(t){return L(t,t)}function ut(t){let e=(1n<<128n)-2n,n=t,r=new Uint8Array(x);for(r[15]=1;e>0n;)(e&1n)===1n&&(r=L(r,n)),n=ft(n),e>>=1n;return r}function dt(){const t=K("66e94bd4ef8a2c3b884cfa59ca342b2e"),e=K("0388dace60b6a392f328c2b971b2fe78"),n=K("42831ec2217774244b7221b784d0d49c"),r=L(e,t),a=L(n,t),o=ae(e,n),s=ae(r,a),i=L(s,ut(o)),c=K("feedfacedeadbeeffeedfacedeadbeef"),d=L(c,i),f=L(c,t);return{deltaCHex:P(o),deltaTHex:P(s),recoveredHHex:P(i),forgedValid:P(d)===P(f),note:"Nonce reuse leaks linear equations in GHASH; with enough structure, H can be solved and forgeries follow."}}function ht(){const t=K("66e94bd4ef8a2c3b884cfa59ca342b2e"),e=K("0388dace60b6a392f328c2b971b2fe78");return P(L(e,t))==="5e2ec746917062882c85b0685353deb7"}const xe=new TextEncoder;function F(t){return Array.from(t,e=>e.toString(16).padStart(2,"0")).join("")}function pt(t){const e=t.trim().toLowerCase();if(!/^[0-9a-f]*$/.test(e)||e.length%2!==0)throw new Error("Expected an even-length hex string");const n=new Uint8Array(e.length/2);for(let r=0;r<n.length;r+=1)n[r]=Number.parseInt(e.slice(r*2,r*2+2),16);return n}function gt(t){return/^[0-9a-fA-F]+$/.test(t)&&t.length%2===0}function Ge(t){const e=t.trim();if(e.length===0)throw new Error("Key must not be empty");return gt(e)?pt(e):xe.encode(t)}async function le(t,e){const n=await crypto.subtle.digest(t,e);return new Uint8Array(n)}function Te(t,e){const n=new Uint8Array(t.length+e.length);return n.set(t,0),n.set(e,t.length),n}async function mt(t,e,n){const r=t==="SHA-256"?64:128,a=new Uint8Array(r),o=e.length>r?await le(t,e):e;a.set(o.slice(0,r));const s=new Uint8Array(r),i=new Uint8Array(r);for(let f=0;f<r;f+=1)s[f]=a[f]^54,i[f]=a[f]^92;const c=await le(t,Te(s,n)),d=await le(t,Te(i,c));return{normalizedKeyHex:F(a),ipadHex:F(s),opadHex:F(i),innerHashHex:F(c),outerHashHex:F(d)}}async function ee(t,e,n){const r=xe.encode(t),a=Ge(e),o=await crypto.subtle.importKey("raw",a,{name:"HMAC",hash:n},!1,["sign"]),s=await crypto.subtle.sign("HMAC",o,r),i=F(new Uint8Array(s)),c=await mt(n,a,r);return{macHex:i,visual:c}}async function yt(t,e){const n=xe.encode(t||"A"),r=Ge(e||"default-key"),a=new Uint8Array(n);a[0]^=1;const o=new Uint8Array(r);o[0]^=1;const s=await ee(t||"A",e||"default-key","SHA-256"),i=await crypto.subtle.importKey("raw",r,{name:"HMAC",hash:"SHA-256"},!1,["sign"]),c=await crypto.subtle.importKey("raw",o,{name:"HMAC",hash:"SHA-256"},!1,["sign"]),d=await crypto.subtle.sign("HMAC",i,a),f=await crypto.subtle.sign("HMAC",c,n);return{original:s.macHex,flippedMessage:F(new Uint8Array(d)),flippedKey:F(new Uint8Array(f))}}async function bt(){const t=new Uint8Array(20).fill(11),e=F(t),n="Hi There",r="b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",a="87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",o=await ee(n,e,"SHA-256"),s=await ee(n,e,"SHA-512");return o.macHex===r&&s.macHex===a}const Pe=new TextEncoder,xt=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298];function I(t,e){return t>>>e|t<<32-e}function wt(t,e,n){return t&e^~t&n}function At(t,e,n){return t&e^t&n^e&n}function Ht(t){return I(t,2)^I(t,13)^I(t,22)}function kt(t){return I(t,6)^I(t,11)^I(t,25)}function Ct(t){return I(t,7)^I(t,18)^t>>>3}function vt(t){return I(t,17)^I(t,19)^t>>>10}function we(t){return Array.from(t,e=>e.toString(16).padStart(2,"0")).join("")}function St(t){const e=t.trim().toLowerCase();if(!/^[0-9a-f]*$/.test(e)||e.length%2!==0)throw new Error("Expected hex string");const n=new Uint8Array(e.length/2);for(let r=0;r<n.length;r+=1)n[r]=Number.parseInt(e.slice(r*2,r*2+2),16);return n}function ge(t){const e=BigInt(t)*8n,n=(t+1)%64,r=n<=56?56-n:56+(64-n),a=new Uint8Array(1+r+8);a[0]=128;for(let o=0;o<8;o+=1)a[a.length-1-o]=Number(e>>BigInt(o*8)&0xffn);return a}function Mt(t){const e=St(t);if(e.length!==32)throw new Error("SHA-256 digest must be 32 bytes");const n=new Uint32Array(8),r=new DataView(e.buffer);for(let a=0;a<8;a+=1)n[a]=r.getUint32(a*4,!1);return n}function Et(t){const e=new Uint8Array(32),n=new DataView(e.buffer);for(let r=0;r<8;r+=1)n.setUint32(r*4,t[r],!1);return we(e)}function Ut(t,e){const n=new Uint32Array(64),r=new DataView(e.buffer,e.byteOffset,e.byteLength);for(let u=0;u<16;u+=1)n[u]=r.getUint32(u*4,!1);for(let u=16;u<64;u+=1)n[u]=vt(n[u-2])+n[u-7]+Ct(n[u-15])+n[u-16]>>>0;let[a,o,s,i,c,d,f,p]=t;for(let u=0;u<64;u+=1){const m=p+kt(c)+wt(c,d,f)+xt[u]+n[u]>>>0,g=Ht(a)+At(a,o,s)>>>0;p=f,f=d,d=c,c=i+m>>>0,i=s,s=o,o=a,a=m+g>>>0}t[0]=t[0]+a>>>0,t[1]=t[1]+o>>>0,t[2]=t[2]+s>>>0,t[3]=t[3]+i>>>0,t[4]=t[4]+c>>>0,t[5]=t[5]+d>>>0,t[6]=t[6]+f>>>0,t[7]=t[7]+p>>>0}function $t(t,e,n){const r=Mt(t),a=e+n.length,o=new Uint8Array(n.length+ge(a).length);o.set(n,0),o.set(ge(a),n.length);for(let s=0;s<o.length;s+=64)Ut(r,o.slice(s,s+64));return Et(r)}function te(t,e){const n=new Uint8Array(t.length+e.length);return n.set(t,0),n.set(e,t.length),n}async function Le(t){const e=await crypto.subtle.digest("SHA-256",t);return we(new Uint8Array(e))}async function _e(t,e,n=16){const r=crypto.getRandomValues(new Uint8Array(n)),a=Pe.encode(t),o=Pe.encode(e),s=await Le(te(r,a)),i=ge(r.length+a.length),c=te(te(a,i),o),d=r.length+a.length+i.length,f=$t(s,d,o),p=await Le(te(r,c));return{originalMessage:t,appendMessage:e,originalMacHex:s,forgedMacHex:f,forgedMessageHex:we(c),verificationMacHex:p,valid:f===p,guessedSecretLength:n}}async function Bt(){return(await _e("comment=10&uid=7","&admin=true",16)).valid}const y=(t,e)=>t[e++]&255|(t[e++]&255)<<8;class Tt{constructor(e){this.blockLen=16,this.outputLen=16,this.buffer=new Uint8Array(16),this.r=new Uint16Array(10),this.h=new Uint16Array(10),this.pad=new Uint16Array(8),this.pos=0,this.finished=!1,e=pe(e),re(e,32);const n=y(e,0),r=y(e,2),a=y(e,4),o=y(e,6),s=y(e,8),i=y(e,10),c=y(e,12),d=y(e,14);this.r[0]=n&8191,this.r[1]=(n>>>13|r<<3)&8191,this.r[2]=(r>>>10|a<<6)&7939,this.r[3]=(a>>>7|o<<9)&8191,this.r[4]=(o>>>4|s<<12)&255,this.r[5]=s>>>1&8190,this.r[6]=(s>>>14|i<<2)&8191,this.r[7]=(i>>>11|c<<5)&8065,this.r[8]=(c>>>8|d<<8)&8191,this.r[9]=d>>>5&127;for(let f=0;f<8;f++)this.pad[f]=y(e,16+2*f)}process(e,n,r=!1){const a=r?0:2048,{h:o,r:s}=this,i=s[0],c=s[1],d=s[2],f=s[3],p=s[4],u=s[5],m=s[6],g=s[7],A=s[8],w=s[9],oe=y(e,n+0),se=y(e,n+2),Ae=y(e,n+4),He=y(e,n+6),ie=y(e,n+8),ke=y(e,n+10),Ce=y(e,n+12),ve=y(e,n+14);let k=o[0]+(oe&8191),C=o[1]+((oe>>>13|se<<3)&8191),v=o[2]+((se>>>10|Ae<<6)&8191),S=o[3]+((Ae>>>7|He<<9)&8191),M=o[4]+((He>>>4|ie<<12)&8191),E=o[5]+(ie>>>1&8191),U=o[6]+((ie>>>14|ke<<2)&8191),$=o[7]+((ke>>>11|Ce<<5)&8191),B=o[8]+((Ce>>>8|ve<<8)&8191),T=o[9]+(ve>>>5|a),l=0,R=l+k*i+C*(5*w)+v*(5*A)+S*(5*g)+M*(5*m);l=R>>>13,R&=8191,R+=E*(5*u)+U*(5*p)+$*(5*f)+B*(5*d)+T*(5*c),l+=R>>>13,R&=8191;let O=l+k*c+C*i+v*(5*w)+S*(5*A)+M*(5*g);l=O>>>13,O&=8191,O+=E*(5*m)+U*(5*u)+$*(5*p)+B*(5*f)+T*(5*d),l+=O>>>13,O&=8191;let _=l+k*d+C*c+v*i+S*(5*w)+M*(5*A);l=_>>>13,_&=8191,_+=E*(5*g)+U*(5*m)+$*(5*u)+B*(5*p)+T*(5*f),l+=_>>>13,_&=8191;let V=l+k*f+C*d+v*c+S*i+M*(5*w);l=V>>>13,V&=8191,V+=E*(5*A)+U*(5*g)+$*(5*m)+B*(5*u)+T*(5*p),l+=V>>>13,V&=8191;let q=l+k*p+C*f+v*d+S*c+M*i;l=q>>>13,q&=8191,q+=E*(5*w)+U*(5*A)+$*(5*g)+B*(5*m)+T*(5*u),l+=q>>>13,q&=8191;let z=l+k*u+C*p+v*f+S*d+M*c;l=z>>>13,z&=8191,z+=E*i+U*(5*w)+$*(5*A)+B*(5*g)+T*(5*m),l+=z>>>13,z&=8191;let j=l+k*m+C*u+v*p+S*f+M*d;l=j>>>13,j&=8191,j+=E*c+U*i+$*(5*w)+B*(5*A)+T*(5*g),l+=j>>>13,j&=8191;let X=l+k*g+C*m+v*u+S*p+M*f;l=X>>>13,X&=8191,X+=E*d+U*c+$*i+B*(5*w)+T*(5*A),l+=X>>>13,X&=8191;let W=l+k*A+C*g+v*m+S*u+M*p;l=W>>>13,W&=8191,W+=E*f+U*d+$*c+B*i+T*(5*w),l+=W>>>13,W&=8191;let Y=l+k*w+C*A+v*g+S*m+M*u;l=Y>>>13,Y&=8191,Y+=E*p+U*f+$*d+B*c+T*i,l+=Y>>>13,Y&=8191,l=(l<<2)+l|0,l=l+R|0,R=l&8191,l=l>>>13,O+=l,o[0]=R,o[1]=O,o[2]=_,o[3]=V,o[4]=q,o[5]=z,o[6]=j,o[7]=X,o[8]=W,o[9]=Y}finalize(){const{h:e,pad:n}=this,r=new Uint16Array(10);let a=e[1]>>>13;e[1]&=8191;for(let i=2;i<10;i++)e[i]+=a,a=e[i]>>>13,e[i]&=8191;e[0]+=a*5,a=e[0]>>>13,e[0]&=8191,e[1]+=a,a=e[1]>>>13,e[1]&=8191,e[2]+=a,r[0]=e[0]+5,a=r[0]>>>13,r[0]&=8191;for(let i=1;i<10;i++)r[i]=e[i]+a,a=r[i]>>>13,r[i]&=8191;r[9]-=8192;let o=(a^1)-1;for(let i=0;i<10;i++)r[i]&=o;o=~o;for(let i=0;i<10;i++)e[i]=e[i]&o|r[i];e[0]=(e[0]|e[1]<<13)&65535,e[1]=(e[1]>>>3|e[2]<<10)&65535,e[2]=(e[2]>>>6|e[3]<<7)&65535,e[3]=(e[3]>>>9|e[4]<<4)&65535,e[4]=(e[4]>>>12|e[5]<<1|e[6]<<14)&65535,e[5]=(e[6]>>>2|e[7]<<11)&65535,e[6]=(e[7]>>>5|e[8]<<8)&65535,e[7]=(e[8]>>>8|e[9]<<5)&65535;let s=e[0]+n[0];e[0]=s&65535;for(let i=1;i<8;i++)s=(e[i]+n[i]|0)+(s>>>16)|0,e[i]=s&65535;Ue(r)}update(e){Ee(this),e=pe(e),re(e);const{buffer:n,blockLen:r}=this,a=e.length;for(let o=0;o<a;){const s=Math.min(r-this.pos,a-o);if(s===r){for(;r<=a-o;o+=r)this.process(e,o);continue}n.set(e.subarray(o,o+s),this.pos),this.pos+=s,o+=s,this.pos===r&&(this.process(n,0,!1),this.pos=0)}return this}destroy(){Ue(this.h,this.r,this.buffer,this.pad)}digestInto(e){Ee(this),Je(e,this),this.finished=!0;const{buffer:n,h:r}=this;let{pos:a}=this;if(a){for(n[a++]=1;a<16;a++)n[a]=0;this.process(n,0,!0)}this.finalize();let o=0;for(let s=0;s<8;s++)e[o++]=r[s]>>>0,e[o++]=r[s]>>>8;return e}digest(){const{buffer:e,outputLen:n}=this;this.digestInto(e);const r=e.slice(0,n);return this.destroy(),r}}function Pt(t){const e=(r,a)=>t(a).update(pe(r)).digest(),n=t(new Uint8Array(32));return e.outputLen=n.outputLen,e.blockLen=n.blockLen,e.create=r=>t(r),e}const Z=Pt(t=>new Tt(t)),J=new TextEncoder,fe=new TextDecoder,Lt=(1n<<130n)-5n,ne=1n<<128n;function Q(t){return Array.from(t,e=>e.toString(16).padStart(2,"0")).join("")}function It(t){const e=t.trim().toLowerCase();if(!/^[0-9a-f]*$/.test(e)||e.length%2!==0)throw new Error("Expected an even-length hex string");const n=new Uint8Array(e.length/2);for(let r=0;r<n.length;r+=1)n[r]=Number.parseInt(e.slice(r*2,r*2+2),16);return n}function me(t){let e=0n;for(let n=t.length-1;n>=0;n-=1)e=(e<<8n)+BigInt(t[n]);return e}function Dt(t,e){let n=t;const r=new Uint8Array(e);for(let a=0;a<e;a+=1)r[a]=Number(n&0xffn),n>>=8n;return r}function Ft(t){const e=new Uint8Array(17);return e.set(t,0),e[t.length]=1,me(e)}function ue(t,e){return Ft(t)*e%Lt}function Ve(){const t=new Uint8Array(32);crypto.getRandomValues(t),t[2]=0,t[3]=0;for(let e=4;e<16;e+=1)t[e]=0;return t}function Rt(t,e){if(t.length!==e.length)return!1;let n=0;for(let r=0;r<t.length;r+=1)n|=t[r]^e[r];return n===0}function Nt(t,e){const n=J.encode(t),r=Ve();if(r.length!==32)throw new Error("Poly1305 key must be exactly 32 bytes (64 hex chars)");const a=Z(n,r);return{tagHex:Q(a),keyHex:Q(r),notes:"Poly1305 key is one-time only. Reusing it breaks authenticity guarantees."}}function Ot(){const t=Ve(),e=J.encode("Invoice=1000USD"),n=J.encode("Invoice=9000USD"),r=J.encode("Invoice=9999USD"),a=Z(e,t),o=Z(n,t),s=me(a),i=me(o);let c=-1n,d=0n;for(let g=0n;g<=0xffffn;g+=1n){const A=ue(e,g),w=(s-A+ne)%ne;if((ue(n,g)+w)%ne===i){c=g,d=w;break}}if(c<0n)throw new Error("Failed to recover weak Poly1305 key; retry demo");const p=(ue(r,c)+d)%ne,u=Dt(p,16),m=Z(r,t);return{msg1:fe.decode(e),msg2:fe.decode(n),msg3:fe.decode(r),tag1Hex:Q(a),tag2Hex:Q(o),forgedTagHex:Q(u),validForgery:Rt(u,m),recoveredRHex:c.toString(16).padStart(4,"0")}}function Kt(){const t=It("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),e=J.encode("Cryptographic Forum Research Group"),n="a8061dc1305136c6c22b8baf0c0127a9",r=Z(e,t);return Q(r)===n}function G(t){return new TextEncoder().encode(t)}function ye(t,e){if(t.length!==e.length)return!1;for(let n=0;n<t.length;n+=1)if(t[n]!==e[n])return!1;return!0}function be(t,e){if(t.length!==e.length)return!1;let n=0;for(let r=0;r<t.length;r+=1)n|=t[r]^e[r];return n===0}function Ie(t,e,n,r){const a=performance.now();for(let s=0;s<r;s+=1)t(e,n);return performance.now()-a}function Gt(t=5e4){const e=G("mac=5f93b8f7ccf93f2af1b047b4f4e8a2d3");return{rows:[{label:"Mismatch at byte 1",value:G("Xac=5f93b8f7ccf93f2af1b047b4f4e8a2d3")},{label:"Mismatch at middle",value:G("mac=5f93b8f7ccf93f2af1b04700f4e8a2d3")},{label:"Mismatch at final byte",value:G("mac=5f93b8f7ccf93f2af1b047b4f4e8a2d4")}].map(a=>({label:a.label,naiveMs:Ie(ye,e,a.value,t),constantMs:Ie(be,e,a.value,t)})),summary:"Naive comparison exits early and leaks prefix-match timing. Constant-time comparison keeps timing flatter."}}function _t(){const t=G("abcdef"),e=G("abcdef"),n=G("abcdeg");return ye(t,e)&&!ye(t,n)&&be(t,e)&&!be(t,n)}function h(t){const e=document.getElementById(t);if(!e)throw new Error(`Missing element: ${t}`);return e}function H(t,e=!1){const n=h("aria-live");n.textContent=t,n.dataset.kind=e?"error":"ok"}function De(t){return t.length>128?`${t.slice(0,128)}...`:t}function Fe(){const t=h("timing-rows");t.textContent="";const e=Gt();for(const n of e.rows){const r=document.createElement("tr"),a=document.createElement("td");a.textContent=n.label;const o=document.createElement("td");o.textContent=`${n.naiveMs.toFixed(3)} ms`;const s=document.createElement("td");s.textContent=`${n.constantMs.toFixed(3)} ms`,r.append(a,o,s),t.appendChild(r)}h("timing-summary").textContent=e.summary}function Vt(t){t.innerHTML=`
    <div class="page" aria-label="MAC Race demo root">
      <a class="skip-link" href="#main-content" aria-label="Skip to main content">Skip to main content</a>
      <header class="hero" aria-label="Header section">
        <div class="hero-top">
          <span class="chip chip-category" aria-label="Category chip">MAC</span>
          <button id="theme-toggle" class="theme-toggle" aria-label="Toggle dark and light mode">Toggle theme</button>
        </div>
        <h1>MAC Race</h1>
        <p class="subtitle">Construction, misuse resistance, and real attack demonstrations for modern Message Authentication Codes.</p>
        <p class="chip-row" aria-label="Primitive chips">HMAC-SHA-256 · HMAC-SHA-512 · AES-CMAC · Poly1305 · GHASH</p>
      </header>

      <main id="main-content" class="panel-grid" aria-label="MAC demo panels">
        <section class="panel" aria-labelledby="p1-title">
          <div class="panel-head">
            <h2 id="p1-title">Panel 1: HMAC</h2>
            <span class="chip chip-ok" aria-label="Status RECOMMENDED DEFAULT">RECOMMENDED DEFAULT</span>
          </div>
          <label for="hmac-message">Message</label>
          <textarea id="hmac-message" aria-label="HMAC message input">transfer=42&to=bob</textarea>
          <label for="hmac-key">Key (text or hex)</label>
          <input id="hmac-key" aria-label="HMAC key input" value="super-secret-key" />
          <button id="hmac-run" aria-label="Compute HMAC results">Compute HMAC</button>
          <pre id="hmac-output" class="hex" aria-label="HMAC output"></pre>
          <pre id="hmac-avalanche" class="hex" aria-label="HMAC avalanche result"></pre>
          <p class="note">FIPS 198-1: HMAC uses nested hashing with ipad/opad, so length extension against bare SHA-256 does not apply.</p>
        </section>

        <section class="panel" aria-labelledby="p2-title">
          <div class="panel-head">
            <h2 id="p2-title">Panel 2: CMAC</h2>
            <span class="chip chip-ok" aria-label="Status RECOMMENDED for FIPS contexts">RECOMMENDED (FIPS contexts)</span>
          </div>
          <label for="cmac-message">Message</label>
          <textarea id="cmac-message" aria-label="CMAC message input">audit-log-entry</textarea>
          <label for="cmac-key">AES-256 key (64 hex or passphrase)</label>
          <input id="cmac-key" aria-label="CMAC key input" value="fips-demo-key" />
          <button id="cmac-run" aria-label="Compute CMAC">Compute CMAC</button>
          <pre id="cmac-output" class="hex" aria-label="CMAC output"></pre>
          <p class="note">NIST SP 800-38B: derives K1/K2 from AES_K(0^128), applies 10* padding, and XORs final block before last encryption.</p>
        </section>

        <section class="panel" aria-labelledby="p3-title">
          <div class="panel-head">
            <h2 id="p3-title">Panel 3: Poly1305</h2>
            <span class="chip chip-ok" aria-label="Status RECOMMENDED with ChaCha20">RECOMMENDED (always use with ChaCha20)</span>
          </div>
          <label for="poly-message">Message</label>
          <textarea id="poly-message" aria-label="Poly1305 message input">Cryptographic Forum Research Group</textarea>
          <button id="poly-run" aria-label="Compute Poly1305 and run key reuse attack">Run Poly1305 demo</button>
          <pre id="poly-output" class="hex" aria-label="Poly1305 output"></pre>
          <pre id="poly-attack" class="hex" aria-label="Poly1305 key reuse attack result"></pre>
          <p class="note">RFC 8439: Poly1305 must use a unique one-time key per message, usually derived by ChaCha20 with a unique nonce.</p>
        </section>

        <section class="panel" aria-labelledby="p4-title">
          <div class="panel-head">
            <h2 id="p4-title">Panel 4: GHASH</h2>
            <span class="chip chip-warn" aria-label="Status secure only with nonce discipline">SECURE when nonce discipline maintained</span>
          </div>
          <label for="ghash-ciphertext">Ciphertext (hex)</label>
          <textarea id="ghash-ciphertext" aria-label="GHASH ciphertext hex input">0388dace60b6a392f328c2b971b2fe78</textarea>
          <button id="ghash-run" aria-label="Compute GHASH and nonce reuse attack">Run GHASH demo</button>
          <pre id="ghash-output" class="hex" aria-label="GHASH output"></pre>
          <pre id="ghash-attack" class="hex" aria-label="GHASH nonce reuse attack result"></pre>
          <p class="note">NIST SP 800-38D: GHASH is linear in GF(2^128). Reusing a GCM nonce is catastrophic.</p>
        </section>

        <section class="panel" aria-labelledby="p5-title">
          <div class="panel-head">
            <h2 id="p5-title">Panel 5: Length Extension Attack</h2>
            <span class="chip chip-bad" aria-label="Status bare SHA-256 as MAC avoid">bare SHA-256 as MAC = AVOID</span>
          </div>
          <label for="le-message">Original message</label>
          <input id="le-message" aria-label="Original message for length extension" value="comment=10&uid=7" />
          <label for="le-append">Attacker append</label>
          <input id="le-append" aria-label="Appended attacker data" value="&admin=true" />
          <button id="le-run" aria-label="Run length extension attack">Run attack</button>
          <pre id="le-output" class="hex" aria-label="Length extension output"></pre>
          <p class="note">Demonstrates real SHA-256 state restoration from digest output; this is why prefix-MAC with bare SHA-256 is unsafe.</p>
        </section>

        <section class="panel" aria-labelledby="p6-title">
          <div class="panel-head">
            <h2 id="p6-title">Panel 6: MAC Comparison + Timing Attack</h2>
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
          <button id="timing-run" aria-label="Measure timing attack differences">Measure timing</button>
          <div class="table-wrap" aria-label="Timing attack measurements">
            <table>
              <caption class="sr-only">Timing attack demonstration: naive versus constant-time MAC comparison</caption>
              <thead><tr><th>Case</th><th>Naive compare</th><th>Constant-time compare</th></tr></thead>
              <tbody id="timing-rows"></tbody>
            </table>
          </div>
          <p id="timing-summary" class="note"></p>
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
  `;const e=document.documentElement;h("theme-toggle").addEventListener("click",()=>{const n=e.dataset.theme==="light"?"dark":"light";e.dataset.theme=n,H(`Theme switched to ${n} mode.`)}),h("hmac-run").addEventListener("click",async()=>{try{const n=h("hmac-message").value,r=h("hmac-key").value,a=await ee(n,r,"SHA-256"),o=await ee(n,r,"SHA-512"),s=await yt(n,r);h("hmac-output").textContent=`HMAC-SHA-256: ${a.macHex}
HMAC-SHA-512: ${o.macHex}
ipad: ${De(a.visual.ipadHex)}
opad: ${De(a.visual.opadHex)}
inner: ${a.visual.innerHashHex}
outer: ${a.visual.outerHashHex}`,h("hmac-avalanche").textContent=`Original : ${s.original}
Flip msg : ${s.flippedMessage}
Flip key : ${s.flippedKey}`,H("HMAC computed successfully.")}catch(n){H(`HMAC error: ${n.message}`,!0)}}),h("cmac-run").addEventListener("click",async()=>{try{const n=h("cmac-message").value,r=h("cmac-key").value,a=await Qe(n,r);h("cmac-output").textContent=`CMAC tag: ${a.tagHex}
AES key: ${a.details.keyHex}
K1: ${a.details.k1Hex}
K2: ${a.details.k2Hex}
Padded last block: ${a.details.paddedLastBlockHex}
Final XOR block: ${a.details.finalXorBlockHex}
Chaining: ${a.details.chainingHex.join(" -> ")||"(single-block message)"}`,H("CMAC computed successfully.")}catch(n){H(`CMAC error: ${n.message}`,!0)}}),h("poly-run").addEventListener("click",()=>{try{const n=h("poly-message").value,r=Nt(n),a=Ot();h("poly-output").textContent=`Poly1305 tag: ${r.tagHex}
One-time key: ${r.keyHex}
GF(2^130 - 5) accumulator uses clamped r and nonce-derived keying.`,h("poly-attack").textContent=`msg1/tag1: ${a.msg1} -> ${a.tag1Hex}
msg2/tag2: ${a.msg2} -> ${a.tag2Hex}
Recovered weak r: 0x${a.recoveredRHex}
Forged tag for ${a.msg3}: ${a.forgedTagHex}
Forgery valid: ${a.validForgery?"YES":"NO"}`,H("Poly1305 demo complete.")}catch(n){H(`Poly1305 error: ${n.message}`,!0)}}),h("ghash-run").addEventListener("click",async()=>{try{const n=h("ghash-ciphertext").value.trim(),r=await lt(n),a=dt();h("ghash-output").textContent=`H = E_K(0^128): ${r.hHex}
GHASH output: ${r.yHex}
Steps: ${r.steps.join(" -> ")}`,h("ghash-attack").textContent=`Delta C: ${a.deltaCHex}
Delta T: ${a.deltaTHex}
Recovered H: ${a.recoveredHHex}
Forgery valid: ${a.forgedValid?"YES":"NO"}
${a.note}`,H("GHASH demo complete.")}catch(n){H(`GHASH error: ${n.message}`,!0)}}),h("le-run").addEventListener("click",async()=>{try{const n=h("le-message").value,r=h("le-append").value,a=await _e(n,r,16);h("le-output").textContent=`Original MAC: ${a.originalMacHex}
Forged message (hex): ${a.forgedMessageHex}
Forged MAC: ${a.forgedMacHex}
Server recomputed: ${a.verificationMacHex}
Forgery valid: ${a.valid?"YES":"NO"}`,H("Length extension attack executed.")}catch(n){H(`Length extension error: ${n.message}`,!0)}}),h("timing-run").addEventListener("click",()=>{Fe(),H("Timing measurements updated.")}),Fe()}async function qt(){const t=await Promise.all([bt(),Ze(),Promise.resolve(Kt()),Promise.resolve(ht()),Bt(),Promise.resolve(_t())]);t.some(e=>!e)&&console.warn("One or more cryptographic self-tests failed.",t)}const qe=document.querySelector("#app");if(!qe)throw new Error("Missing #app container");document.documentElement.dataset.theme="dark";Vt(qe);qt();
