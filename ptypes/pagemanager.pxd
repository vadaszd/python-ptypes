

cdef initPageManager()
cdef int pagesize


cdef class MemoryMappedFile(object):
    cdef:
        readonly str    fileName
        long            fd
        int             isNew
        readonly unsigned long long    numPages, realFileSize

    cpdef flush(self, bint async=?)
    cpdef close(self)

    cdef inline assertNotClosed(self):
        if self.baseAddress == NULL:
            raise ValueError(
                'MemoryMappedFile {self.fileName} is closed.'
                .format(self=self))


DEF lengthOfMagic = 31
DEF numMetadata = 2

