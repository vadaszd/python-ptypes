cdef extern from "avl-tree.h" nogil:

    ctypedef struct AVLTree:
        pass


from libc.stdlib cimport abort

cdef enum:
    lengthOfMagic = 31
    numMetadata = 2

ctypedef unsigned long Offset


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
        Offset          o2payloadArea
        AdminMapping    adminMapping

#     cpdef flush(self, bint async=?)
    cpdef close(self)

    cdef inline assertNotClosed(self):
        if self.adminMapping is None:
            raise ValueError(
                'BackingFile {} is closed.'
                .format(self.fileName))

cdef struct CRegion:
    void   *baseAddress   # address of 1st byte included
    void   *endAddress    # address of 1st byte excluded
    size_t  length        # end-base
    long    fd            # file descriptor of the underlying file
    Offset  o2Base
    AVLTree *dirtyPages


cdef class FileMapping(object):
    cdef:
        BackingFile         backingFile
        CRegion             region          # covers the whole file
        CRegion             adminRegion     # covers the admin area (header)
        CRegion             payloadRegion   # covers the payload area

        str __formatErrorMessage(self, CRegion *region, str message, 
                                 int error=?, fileName=?)
        map(self, CRegion *region, )
#         flush(CRegion* region, bint async=0)


cdef class AdminMapping(FileMapping):
    cdef:
        CBackingFileHeader       *p2FileHeaders[numMetadata]
        CBackingFileHeader       *p2FileHeader

        protect(self, CRegion *region, int protectionMode)
        flush(self, CRegion *region, bint async=?)
        initialize(self)
        mount(self)
        sync(self, Trx trx, bint doFlush=?)


cdef class Trx(FileMapping):
    """ An atomically updateable memory region mapped into a file
    """
    cdef:
        close(Trx self, type Persistent, bint doCommit)
        updatePayload(self, void *targetRegionBaseAddress)


    cdef inline assertNotClosed(self):
        if self.region.baseAddress == NULL:
            raise ValueError(
                'This transaction on {} is closed.'
                .format(self.backingFile.fileName))

    cdef inline void*  offset2Address(self, Offset offset) except NULL:
        self.assertNotClosed()
        if self.backingFile.realFileSize < offset:
            print(
                "Corruption: offset {offset} is outside the mapped memory!"
                " - Aborting.".format(offset=offset))
            abort()
        return self.region.baseAddress + offset

    cdef inline Offset address2Offset(self, 
                                      const void* address) except 0:
        assert address > self.region.baseAddress
        cdef Offset offset = address - self.region.baseAddress
        assert offset < self.backingFile.realFileSize
        return offset



