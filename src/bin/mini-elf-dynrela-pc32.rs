use std::{env, ffi::OsString, fs, process::ExitCode};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_W: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const R_X86_64_PC32: u32 = 2;

#[derive(Clone, Copy)]
struct Phdr {
    kind: u32,
    flags: u32,
    off: u64,
    va: u64,
    filesz: u64,
    memsz: u64,
}

fn main() -> ExitCode {
    match run(env::args_os().skip(1)) {
        Ok(s) => { print!("{s}"); ExitCode::SUCCESS }
        Err(e) => { eprintln!("error: {e}"); ExitCode::FAILURE }
    }
}

fn run<I: Iterator<Item = OsString>>(args: I) -> Result<String, String> {
    let inputs: Vec<_> = args.collect();
    if inputs.is_empty() { return Err("usage: mini-elf-dynrela-pc32 <input>...".into()); }
    let mut out = Vec::new();
    for p in &inputs {
        let name = p.to_string_lossy().into_owned();
        let b = fs::read(p).map_err(|e| format!("cannot read '{name}': {e}"))?;
        out.push((name, inspect(&b)?));
    }
    let multi = out.len() > 1;
    let mut text = String::new();
    for (i, (name, body)) in out.into_iter().enumerate() {
        if i != 0 { text.push('\n'); }
        if multi { text.push_str(&format!("File: {name}\n")); }
        text.push_str(&body);
    }
    Ok(text)
}

fn inspect(b: &[u8]) -> Result<String, String> {
    if b.len() < 64 || &b[..4] != b"\x7fELF" || b[4] != 2 || b[5] != 1 {
        return Err("requires little-endian ELF64 input".into());
    }
    if u16at(b, 16) != 3 || u16at(b, 18) != 62 { return Err("requires x86-64 ET_DYN input".into()); }
    let hs = phdrs(b)?;
    let dynh: Vec<_> = hs.iter().copied().filter(|h| h.kind == PT_DYNAMIC).collect();
    if dynh.len() != 1 { return Err("requires exactly one PT_DYNAMIC".into()); }
    let db = file_range(b, dynh[0].off, dynh[0].filesz, "PT_DYNAMIC")?;
    if db.len() % 16 != 0 { return Err("PT_DYNAMIC size is not a multiple of 16".into()); }
    let mut hash=None; let mut sym=None; let mut syment=None; let mut strtab=None; let mut strsz=None;
    let mut rela=None; let mut relasz=None; let mut relaent=None; let mut term=false;
    for (i,e) in db.chunks_exact(16).enumerate() {
        let t=i64at(e,0); let v=u64at(e,8);
        if t==DT_NULL { term=true; break; }
        let slot = match t {
            DT_HASH=>&mut hash, DT_SYMTAB=>&mut sym, DT_SYMENT=>&mut syment,
            DT_STRTAB=>&mut strtab, DT_STRSZ=>&mut strsz, DT_RELA=>&mut rela,
            DT_RELASZ=>&mut relasz, DT_RELAENT=>&mut relaent, _=>continue
        };
        if slot.replace(v).is_some() { return Err(format!("duplicate dynamic tag at entry {i}")); }
    }
    if !term { return Err("PT_DYNAMIC lacks DT_NULL".into()); }
    let hash=req(hash,"DT_HASH")?; let sym=req(sym,"DT_SYMTAB")?; let syment=req(syment,"DT_SYMENT")?;
    let strtab=req(strtab,"DT_STRTAB")?; let strsz=req(strsz,"DT_STRSZ")?; let rela=req(rela,"DT_RELA")?;
    let relasz=req(relasz,"DT_RELASZ")?; let relaent=req(relaent,"DT_RELAENT")?;
    if syment!=24 || relaent!=24 || relasz%24!=0 { return Err("unsupported dynamic table entry size".into()); }
    let hb=map(b,&hs,hash,8,0,"DT_HASH")?; let n=u64::from(u32at(hb,4));
    if n==0 { return Err("DT_HASH reports zero symbols".into()); }
    let sb=map(b,&hs,sym,n.checked_mul(24).ok_or("dynsym size overflow")?,0,"DT_SYMTAB")?;
    let st=map(b,&hs,strtab,strsz,0,"DT_STRTAB")?; let rb=map(b,&hs,rela,relasz,0,"DT_RELA")?;
    let mut text=format!("Validated R_X86_64_PC32 relocations: entries={} symbols={n}\n",relasz/24);
    let mut found=0;
    for (i,r) in rb.chunks_exact(24).enumerate() {
        let off=u64at(r,0); let info=u64at(r,8); if info as u32 != R_X86_64_PC32 { continue; }
        let si=info>>32; if si==0 || si>=n { return Err(format!("R_X86_64_PC32 relocation {i} has invalid symbol index {si}")); }
        mem(&hs,off,4,PF_W,"PC32 target")?;
        let so=usize::try_from(si.checked_mul(24).ok_or("symbol offset overflow")?).map_err(|_|"symbol offset too large")?;
        let s=&sb[so..so+24]; let no=u32at(s,0) as usize; let sh=u16at(s,6); let sv=u64at(s,8);
        if no>=st.len() { return Err(format!("dynamic symbol {si} name offset is outside DT_STRTAB")); }
        let tail=&st[no..]; let z=tail.iter().position(|x|*x==0).ok_or("dynamic symbol name is not NUL-terminated")?;
        let name=std::str::from_utf8(&tail[..z]).map_err(|_|"dynamic symbol name is not UTF-8")?;
        let a=i64at(r,16);
        if sh==0 {
            text.push_str(&format!("  index={i} symbol={si}:{name} binding=external target={off:#x} addend={a} formula=S+A-P\n"));
        } else {
            mem(&hs,sv,1,0,"PC32 symbol")?;
            let v=i128::from(sv)+i128::from(a)-i128::from(off);
            i32::try_from(v).map_err(|_|format!("R_X86_64_PC32 relocation {i} result does not fit i32"))?;
            text.push_str(&format!("  index={i} symbol={si}:{name} binding=same-image target={off:#x} addend={a} result={v}\n"));
        }
        found+=1;
    }
    if found==0 { return Err("DT_RELA contains no R_X86_64_PC32 relocations".into()); }
    Ok(text)
}

fn phdrs(b:&[u8])->Result<Vec<Phdr>,String>{
    let off=usize::try_from(u64at(b,32)).map_err(|_|"phoff too large")?; let ents=usize::from(u16at(b,54)); let n=usize::from(u16at(b,56));
    if ents!=56 { return Err("unsupported program-header size".into()); }
    let end=off.checked_add(n.checked_mul(ents).ok_or("program-header size overflow")?).ok_or("program-header range overflow")?;
    if end>b.len(){return Err("program-header table exceeds input".into())}
    let mut v=Vec::with_capacity(n);
    for i in 0..n { let p=off+i*ents; let h=Phdr{kind:u32at(b,p),flags:u32at(b,p+4),off:u64at(b,p+8),va:u64at(b,p+16),filesz:u64at(b,p+32),memsz:u64at(b,p+40)};
        if h.filesz>h.memsz{return Err(format!("program header {i} filesz exceeds memsz"))} file_range(b,h.off,h.filesz,"program header")?; h.va.checked_add(h.memsz).ok_or("segment address overflow")?; v.push(h); }
    Ok(v)
}
fn file_range<'a>(b:&'a[u8],off:u64,size:u64,label:&str)->Result<&'a[u8],String>{let s=usize::try_from(off).map_err(|_|format!("{label} offset too large"))?;let w=usize::try_from(size).map_err(|_|format!("{label} size too large"))?;let e=s.checked_add(w).ok_or_else(||format!("{label} range overflow"))?;if e>b.len(){return Err(format!("{label} exceeds input"))}Ok(&b[s..e])}
fn map<'a>(b:&'a[u8],hs:&[Phdr],va:u64,size:u64,flags:u32,label:&str)->Result<&'a[u8],String>{let end=va.checked_add(size).ok_or_else(||format!("{label} address overflow"))?;for h in hs.iter().filter(|h|h.kind==PT_LOAD&&h.flags&flags==flags){let he=h.va+h.filesz;if va>=h.va&&end<=he{return file_range(b,h.off+(va-h.va),size,label)}}Err(format!("{label} is not file-backed by PT_LOAD"))}
fn mem(hs:&[Phdr],va:u64,size:u64,flags:u32,label:&str)->Result<(),String>{let end=va.checked_add(size).ok_or_else(||format!("{label} address overflow"))?;for h in hs.iter().filter(|h|h.kind==PT_LOAD&&h.flags&flags==flags){if va>=h.va&&end<=h.va+h.memsz{return Ok(())}}Err(format!("{label} is not contained in matching PT_LOAD"))}
fn req(v:Option<u64>,n:&str)->Result<u64,String>{v.ok_or_else(||format!("missing {n}"))}
fn u16at(b:&[u8],o:usize)->u16{u16::from_le_bytes(b[o..o+2].try_into().unwrap())}
fn u32at(b:&[u8],o:usize)->u32{u32::from_le_bytes(b[o..o+4].try_into().unwrap())}
fn u64at(b:&[u8],o:usize)->u64{u64::from_le_bytes(b[o..o+8].try_into().unwrap())}
fn i64at(b:&[u8],o:usize)->i64{i64::from_le_bytes(b[o..o+8].try_into().unwrap())}
