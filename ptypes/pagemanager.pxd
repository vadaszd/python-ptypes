

cdef struct CBackingFileHeader:
    char magic[lengthOfMagic]
    char status
    unsigned long revision
    unsigned long lastAppliedRedoFileNumber
    Offset o2lastAppliedTrx


cdef class BackingFile(object):
    cdef:
        readonly str    fileName
        long            fd
        bint            isNew
        size_t          numPages, realFileSize

        CBackingFileHeader       *p2FileHeaders[numMetadata]
        CBackingFileHeader       *p2HiHeader
        CBackingFileHeader       *p2LoHeader
        CBackingFileHeader       *p2FileHeader

    cpdef flush(self, bint async=?)
    cpdef close(self)


cdef struct CProtectedRegion:
    void *baseAddress   # address of 1st byte included
    void *endAddress    # address of 1st byte excluded
    size_t length       # end-base


cdef class Trx(object):
    """ An atomically updateable memory region mapped into a file
    """
    cdef:
        BackingFile         backingFile
        CProtectedRegion    *region

        Trx close(Trx self, type Persistent, bint doCommit)

    cdef inline assertNotClosed(self):
        if self.region.baseAddress == NULL:
            raise ValueError(
                'BackingFile {} is closed.'
                .format(self.backingFile.fileName))

    cdef inline void*  offset2Address(self, Offset offset) except NULL:
        self.assertNotClosed()
        if self.backingFile.realFileSize < offset:
            print(
                "Corruption: offset {offset} is outside the mapped memory!"
                " - Aborting.".format(offset=offset))
            abort()
        return self.region.baseAddress + offset

    cdef inline Offset address2Offset(PersistentMeta ptype, 
                                      const void* address) except 0:
        assert address > self.region.baseAddress
        cdef Offset offset = address - self.region.baseAddress
        assert offset < self.backingFile.realFileSize
        return offset



DEF lengthOfMagic = 31
DEF numMetadata = 2

