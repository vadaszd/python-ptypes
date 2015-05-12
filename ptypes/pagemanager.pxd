

cdef initPageManager()
cdef int pagesize

cdef struct CProtectedRegion:
    void *baseAddress
    size_t length
    void *endAddress

cdef CProtectedRegion *CProtectedRegion_new(void *baseAddress,
                                            size_t length,) except NULL
cdef CProtectedRegion *CProtectedRegion_setCurrent(CProtectedRegion *region)
# cdef int CProtectedRegion_protect(CProtectedRegion *region)