import idc
import idautils
import ida_bytes
import ida_search
import ida_idaapi
import ida_segment
import ida_typeinf
import ida_nalt
import ida_ida

try:
    ModuleNotFoundError
except NameError:
    ModuleNotFoundError = ImportError

ida_9_or_later = False
try:
    import ida_struct
    from ida_struct import get_member_by_name
except ModuleNotFoundError:
    ida_9_or_later = True

    def get_member_by_name(tif, name):
        if not tif.is_struct():
            return None

        udm = ida_typeinf.udm_t()
        udm.name = name
        idx = tif.find_udm(udm, ida_typeinf.STRMEM_NAME)
        if idx != -1:
            return udm
        return None


class utils(object):
    DATA_SEGMENT_CLASSES = {"DATA", "CONST", "BSS", "STRLIT", "INIT", "XTRN"}

    def __init__(self):
        self.text = None
        self.data = None
        self.rdata = None
        self.code_segments = []
        self.data_segments = []
        self.valid_ranges = []
        self.refresh_segments()

        self.x64 = False
        try:
            self.x64 = bool(ida_ida.inf_is_64bit())
        except AttributeError:
            inf = None
            get_inf = getattr(ida_idaapi, "get_inf_structure", None)
            if callable(get_inf):
                inf = get_inf()
            if inf and hasattr(inf, "is_64bit"):
                self.x64 = bool(inf.is_64bit())
            else:
                try:
                    self.x64 = bool(ida_idaapi.cvar.inf.is_64bit())
                except AttributeError:
                    lflags = getattr(ida_idaapi.cvar.inf, "lflags", 0)
                    self.x64 = bool(lflags & getattr(ida_ida, "LFLG_64BIT", 0))

        if self.x64:
            self.PTR_TYPE = ida_bytes.FF_QWORD
            self.REF_OFF = ida_nalt.REF_OFF64
            self.PTR_SIZE = 8
            self.get_ptr = ida_bytes.get_64bit
        else:
            self.PTR_TYPE = ida_bytes.FF_DWORD
            self.REF_OFF = ida_nalt.REF_OFF32
            self.PTR_SIZE = 4
            self.get_ptr = ida_bytes.get_32bit

    def refresh_segments(self):
        self.code_segments = []
        self.data_segments = []

        preferred_text = ida_segment.get_segm_by_name(".text")
        preferred_data = ida_segment.get_segm_by_name(".data")
        preferred_rdata = ida_segment.get_segm_by_name(".rdata")

        self.text = preferred_text
        self.data = preferred_data
        self.rdata = preferred_rdata

        seg_qty = ida_segment.get_segm_qty()
        for idx in range(seg_qty):
            seg = ida_segment.getnseg(idx)
            if not seg or seg.is_header_segm():
                continue

            seg_name = ida_segment.get_segm_name(seg) or ""
            lname = seg_name.lower()
            seg_class = ida_segment.get_segm_class(seg)
            perms = getattr(seg, "perm", -1)
            if perms == -1:
                perms = ida_segment.get_segm_attr(seg.start_ea, ida_segment.SEGATTR_PERM)
            if perms == -1:
                perms = 0

            is_exec = bool(perms & ida_segment.SEGPERM_EXEC)
            is_read = bool(perms & ida_segment.SEGPERM_READ)

            if seg_class == "CODE" or is_exec:
                self.code_segments.append(seg)
                if self.text is None and (lname.startswith(".text") or is_exec):
                    self.text = seg
                continue

            is_data_like = seg_class in self.DATA_SEGMENT_CLASSES or (is_read and not is_exec)
            if not is_data_like:
                continue

            self.data_segments.append(seg)
            if self.data is None and lname.startswith(".data"):
                self.data = seg
            if self.rdata is None and lname.startswith(".rdata"):
                self.rdata = seg

        if self.text is None and self.code_segments:
            self.text = self.code_segments[0]
        self.valid_ranges = [(seg.start_ea, seg.end_ea) for seg in self.data_segments]

    def get_data_segments(self):
        if not self.data_segments:
            self.refresh_segments()
        return list(self.data_segments)

    def update_valid_ranges(self):
        self.refresh_segments()

    def get_candidate_data_segments(self):
        segments = []
        seen = set()

        def add_segment(seg):
            if seg is None:
                return
            key = (seg.start_ea, seg.end_ea)
            if key in seen:
                return
            segments.append(seg)
            seen.add(key)

        add_segment(self.rdata)
        add_segment(self.data)
        for seg in self.get_data_segments():
            add_segment(seg)
        return segments

    # for 32-bit binaries, the RTTI structs contain absolute addresses, but for
    # 64-bit binaries, they're offsets from the image base.
    def x64_imagebase(self):
        if self.x64:
            return ida_nalt.get_imagebase()
        return 0

    def get_strlen(self, addr, max_len=500):
        strlen = 0
        while ida_bytes.get_byte(addr+strlen) != 0x0 and strlen < max_len:
            strlen += 1
        if strlen == max_len:
            return None
        return strlen

    def is_vtable(self, addr):
        function = self.get_ptr(addr)
        if not ida_bytes.has_xref(ida_bytes.get_full_flags(addr)):
            return False
        if function == ida_idaapi.BADADDR:
            return False
        for seg in self.code_segments:
            if seg.start_ea <= function <= seg.end_ea:
                return True
        return ida_bytes.is_code(ida_bytes.get_full_flags(function))

    def within(self, value, ranges):
        if not ranges:
            return True
        return any(start <= value <= end for start, end in ranges)

    @staticmethod
    def to_signed32(n):
        n = n & 0xffffffff
        return n | (-(n & 0x80000000))

    @staticmethod
    def get_refs_to(ea):
        for xref in idautils.XrefsTo(ea, 0):
            yield xref.frm

    @classmethod
    def get_refs_to_by_type_name(cls, name):
        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(None, name, ida_typeinf.BTF_STRUCT):
            for xref in cls.get_refs_to(tif.get_tid()):
                yield xref
                
    def add_ptr_or_rva_member(self, sid, mname, mtype_name, array=False, idx=-1):
        # if idx is not specified, insert the member at the end of the structure
        if idx < 0:
            idx = idc.get_member_qty(sid)
            
        idc.add_struc_member(sid, mname, ida_idaapi.BADADDR, ida_bytes.FF_DATA|ida_bytes.FF_DWORD|ida_bytes.FF_0OFF, -1, 4)
        self.set_ptr_or_rva_member(sid, mname, mtype_name, array, idx)
        
    def set_ptr_or_rva_member(self, sid, mname, mtype_name, array=False, idx=-1):
        sname = idc.get_struc_name(sid)
        
        # if idx is not specified, modifie the last member
        if idx < 0:
            idx = idc.get_member_qty(sid) - 1
            
        r = None
        if self.x64:
            reftype = ida_nalt.REFINFO_RVAOFF|self.REF_OFF
            mtif = get_ptr_type(mtype_name, ptr_size=ida_typeinf.TAPTR_PTR32, array=array)
            if ida_9_or_later:
                r = get_val_repr(ida_typeinf.FRB_OFFSET, reftype)
        else:
            reftype = self.REF_OFF
            mtif = get_ptr_type(mtype_name, ptr_size=0, array=array)
            
        if ida_9_or_later:
            tif = ida_typeinf.tinfo_t()
            tif.get_named_type(None, sname)
            udt = ida_typeinf.udt_type_data_t()
            tif.set_udm_type(idx, mtif, 0, r)
            tif.get_udt_details(udt)
        else:
            s = ida_struct.get_struc(sid)
            ida_struct.set_member_tinfo(s, s.get_member(idx), 0, mtif, 0)
            idc.set_member_type(sid, idc.get_member_offset(sid, mname), ida_bytes.FF_DATA|ida_bytes.FF_DWORD|ida_bytes.FF_0OFF, -1, 1, reftype=reftype)
        
    @staticmethod
    def get_moff_by_name(struc, name):
        try:
            offset = get_member_by_name(struc, name).soff
        except AttributeError:
            # for ida 9.0
            offset = get_member_by_name(struc, name).offset // 8
        return offset
    
    @classmethod
    def get_cols_by_col(cls, col, vftables):
        # get offsets in COLs by finding xrefs for multiple inheritance
        x = set([xrea for xrea in cls.get_refs_to(col.tdea)])
        y = set([xrea for xrea in cls.get_refs_to(col.tid)])
        # If the target is a multi inheritance class, TD or CHD has multiple xrefs from multiple COLs.
        # Here, get the COLs
        coleas = (x&y)
        cols = sorted(list(filter(lambda x: x.ea in coleas, vftables.values())), key=lambda x: x.ea in coleas)
        return cols

    @classmethod
    def get_col_offs_by_cols(cls, cols):
        col_offs = [ida_bytes.get_32bit(x.ea+cls.get_moff_by_name(x.struc, "offset")) for x in cols]
        return col_offs

    @classmethod
    def get_col_offs(cls, col, vftables):
        cols = cls.get_cols_by_col(col, vftables)
        # get the offsets in COLs
        col_offs = cls.get_col_offs_by_cols(cols)
        return col_offs

    @classmethod
    def get_col_bases(cls, col, vftables):
        # for checking if a class has multiple vftables or not
        col_offs = cls.get_col_offs(col, vftables)
        
        bases = []
        paths = col.chd.bca.paths.get(col.offset, [])
        for path in paths:
            append = False
            for bcd in path:
                # for SI and MI but there is only a vftable
                if len(col_offs) < 2:
                    append = True
                # for MI and there are multiple vftables
                elif bcd.mdisp == col.offset:
                    append = True
                elif bcd.pdisp >= 0:
                    append = True
                # if append flag is enabled, append it and subsequent BCDs after it
                if append and bcd not in bases:
                    bases.append(bcd)
        return bases


def add_struc_by_name_and_def(name, struc_def):
    tif = ida_typeinf.tinfo_t(struc_def)
    tif.set_named_type(None, name, ida_typeinf.NTF_REPLACE)
    return tif


def build_udm(tif, name, msize=0, mtype=ida_typeinf.BTF_INT, moffset=-1, vrepr=None):
    # create a struct member
    udm = ida_typeinf.udm_t()
    udm.name = name
    if msize > 0:
        udm.size = msize * 8
        
    udm.offset = tif.get_unpadded_size() * 8
    if moffset >= 0:
        udm.offset = moffset * 8
        
    udm.type = ida_typeinf.tinfo_t(mtype)
    
    if vrepr:
        udm.set_value_repr(vrepr)
        
    return udm


def add_struc(name):
    tif = ida_typeinf.tinfo_t()
    udt = ida_typeinf.udt_type_data_t()
    # add the structure to local types
    if tif.create_udt(udt):
        tif.set_named_type(None, name)
    return tif


def add_struc_member(tif, name, msize=0, mtype=None, moffset=-1, vrepr=None):
    udm = build_udm(tif, name, msize, mtype, moffset, vrepr)
    tif.add_udm(udm, ida_typeinf.ETF_MAY_DESTROY|ida_typeinf.ETF_FORCENAME)
    return udm


def create_ptr_attr(data_type=ida_typeinf.BTF_INT, attr=ida_typeinf.TAPTR_PTR32):
    # pointer description
    pi = ida_typeinf.ptr_type_data_t()
    pi.obj_type = ida_typeinf.tinfo_t(data_type)
    pi.taptr_bits = attr
    # pointer type
    mtif = ida_typeinf.tinfo_t()
    mtif.create_ptr(pi)
    return mtif


def get_ptr_type(type_name, ptr_size=ida_typeinf.TAPTR_PTR32, array=False):
    mtif = ida_typeinf.tinfo_t()
    if mtif.get_named_type(None, type_name):
        # for 64-bit, the member stores an RVA.
        # create "*__ptr32" here.
        if ptr_size:
            mtif = create_ptr_attr(mtif, ptr_size)
        # for 32-bit, the member stores a pointer.
        # just create a pointer
        else:
            mtif.create_ptr(mtif)
            
        # for BCA
        if array:
            mtif.create_array(mtif)
        return mtif
    return None


"""
def get_refinfo(reftype=ida_nalt.REF_OFF64, flags=ida_nalt.REFINFO_RVAOFF):
    ri = ida_nalt.refinfo_t()
    ri.flags = flags
    ri.target = 0
    ri.set_type(reftype)
    return ri


def get_offset_refinfo(reftype=ida_nalt.REF_OFF64, flags=ida_nalt.REFINFO_RVAOFF):
    ri = get_refinfo(reftype, flags)
    vr = ida_typeinf.value_repr_t()
    vr.set_vtype(ida_typeinf.FRB_OFFSET)
    vr.ri = ri
    return vr


def set_opinfo(tif, udt, udt_idx):
    oi = ida_nalt.opinfo_t()
    oi.ri = get_refinfo(reftype=ida_nalt.REF_OFF64, flags=ida_nalt.REFINFO_RVAOFF)
    mtif = create_ptr_attr(ida_typeinf.BTF_INT, ida_typeinf.TAPTR_PTR32)
    flags = ida_bytes.off_flag()
    # Apply the offset and RVA attributes to udm target.
    udt[udt_idx].repr.from_opinfo(flags, 0, oi, None)
    tif.set_udm_repr(udt_idx, udt[udt_idx].repr)
    tif.set_udm_type(udt_idx, mtif)
"""


def get_val_repr(vtype=-1, flags=ida_nalt.REF_OFF64|ida_nalt.REFINFO_RVAOFF):
    if vtype < 0:
        vtype = ida_typeinf.FRB_OFFSET
    r = ida_typeinf.value_repr_t()
    r.set_vtype(vtype)
    r.ri.init(flags)
    return r


"""
struc_def = '''
struct RTTICompleteObjectLocator
{
  int signature;
  int offset;
  int cdOffset;
  int pTypeDescriptor;
  int pClassDescriptor;
  int pSelf;
};
'''
name = "RTTICompleteObjectLocator"
tif = add_struc_by_name_and_def(name, struc_def)

r = get_val_repr(ida_typeinf.FRB_OFFSET, ida_nalt.REF_OFF64|ida_nalt.REFINFO_RVAOFF)
mtif = create_ptr_attr(ida_typeinf.BTF_INT, ida_typeinf.TAPTR_PTR32)
for i in range(3, 6):
    tif.set_udm_type(i, mtif, 0, r)
ida_typeinf.apply_tinfo(here(), tif, ida_typeinf.TINFO_DEFINITE)
"""


def get_value_with_size(val, vsize):
    off_v = ida_idaapi.BADADDR
    if vsize == 8:
        off_v = ida_bytes.get_qword(val)
    elif vsize == 4:
        off_v = ida_bytes.get_dword(val)
    elif vsize == 2:
        off_v = ida_bytes.get_word(val)
    elif vsize == 1:
        off_v = ida_bytes.get_byte(val)
    return off_v


def get_offset_ptr(v, force_bitness=False):
    target_ea = ida_idaapi.BADADDR
    if v == ida_idaapi.BADADDR:
        return target_ea
    flags = ida_bytes.get_full_flags(v)
    if not force_bitness and ida_bytes.is_qword(flags):
        target_ea = get_value_with_size(v, 8)
    elif not force_bitness and ida_bytes.is_dword(flags):
        target_ea = get_value_with_size(v, 4)
    else:
        seg = ida_segment.getseg(v)
        if seg is None:
            return target_ea
        off_size = 1<<(seg.bitness+1)
        target_ea = get_value_with_size(v, off_size)
    return target_ea


def get_offset_fptr(v, force_bitness=False):
    target_ea = ida_idaapi.BADADDR
    tmp_ea = get_offset_ptr(v, force_bitness)
    flags = ida_bytes.get_full_flags(tmp_ea)
    if ida_bytes.is_code(flags):
        target_ea = tmp_ea
    return target_ea


def get_vtbl_methods(target_ea):
    prev_target_ea = target_ea
    item_diff = 8
    seg = ida_segment.getseg(target_ea)
    next_name_ea = ida_ida.inf_get_max_ea()
    if seg:
        item_diff = 1<<(seg.bitness+1)
        # get next label that has a xref
        next_name_ea = ida_bytes.next_that(target_ea, seg.end_ea, ida_bytes.has_xref)
        if next_name_ea == ida_idaapi.BADADDR:
            next_name_ea = seg.end_ea
    
    ea = get_offset_fptr(target_ea, force_bitness=True)
    while target_ea != ida_idaapi.BADADDR and target_ea < next_name_ea and ea != ida_idaapi.BADADDR:
        flags = ida_bytes.get_full_flags(ea)
        if ida_bytes.is_code(flags):
            yield ea
        else:
            break
        
        prev_target_ea = target_ea
        target_ea = ida_search.find_data(target_ea, ida_search.SEARCH_DOWN|ida_search.SEARCH_NEXT)
        if target_ea - prev_target_ea != item_diff:
            break
        ea = get_offset_fptr(target_ea, force_bitness=True)

