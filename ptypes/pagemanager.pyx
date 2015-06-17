

cdef extern from "sys/mman.h":
    void *mmap(void *addr, size_t length, int prot, int flags, int fd,
               int offset)
    int munmap(void *addr, size_t length)
    int mprotect(void *addr, size_t len, int prot)
    int PROT_READ, PROT_WRITE, PROT_NONE
    int MAP_SHARED, MAP_PRIVATE  # flags
    void *MAP_FAILED

cdef extern from "signal.h" nogil:
    enum: SIGSEGV
    enum: SEGV_ACCERR

cdef extern from "unistd.h" nogil:
    int getpagesize()

from posix.signal cimport sigaction_t, siginfo_t
from posix.signal cimport sigaction, sigemptyset, SA_SIGINFO
from libc.stdio cimport perror
from libc.errno cimport errno
from libc.stdlib cimport malloc, free
from libc.string import strerror, memcpy

cdef char *ptypesMagic     = "ptypes-0.6.0"       # Maintained by bumpbersion,
cdef char *ptypesRedoMagic = "redo-ptypes-0.6.0"  # no manual changes please!

cdef extern from "errno.h":
    int errno

# cdef extern from "string.h":
#     char *strerror(int errnum)
#     void *memcpy(void dest, const void src, size_t n)


import os


cdef class BackingFile(object):

    def __init__(self, str fileName, size_t fileSize=0):
        self.fileName = fileName
        try:
            self.fd = os.open(self.fileName, os.O_RDWR)
        except OSError:
            self.numPages = (0 if fileSize==0 else 
                             (fileSize-1)/pagesize + 1 + numMetadata)
            LOG.debug("Creating new file '{self.fileName}'".format(self=self))
            assert numPages > 0, ('The database cannot have {numPages} pages.'
                                  .format(numPages=self.numPages)
                                  )
            self.isNew = 1
            self.realFileSize = self.numPages * pagesize
            self.fd = os.open(self.fileName, O_CREAT | O_RDWR)
            os.lseek(self.fd, self.realFileSize-1, SEEK_SET)
            os.write(self.fd, b'\x00')
        else:
            LOG.debug(
                "Opened existing file '{self.fileName}'".format(self=self))
            self.isNew = 0
            self.realFileSize = os.fstat(self.fd).st_size
            self.numPages = int(self.realFileSize / pagesize)
        cdef int error=0
#         self.region = CProtectedRegion_new(xxx) xxx xxx
        if self.isNew:
            self._initialize()
        else:
            self._mount()
        LOG.debug("Highest metadata revision is {0}"
                  .format(self.p2HiHeader.revision))
        LOG.debug("Lowest metadata revision is {0}"
                  .format(self.p2LoHeader.revision))
        LOG.debug("Using metadata revision {0}"
                  .format(self.p2FileHeader.revision))
        if not self.isNew and fileSize > self.realFileSize:
            raise Exception("File {self.fileName} is of size "
                            "{self.realFileSize}, cannot resize it to "
                            "{fileSize}.".format(self=self, fileSize=fileSize)
                            )

    def _initialize(self):
        LOG.info("Initializing new file '{self.fileName}'".format(self=self))
        assert len(ptypesMagic) < lengthOfMagic
        cdef int i

        for i in range(numMetadata):
            self.p2FileHeader = self.p2FileHeaders[i] = \
                            <CStorageHeader*>self.baseAddress + i*pagesize
            memcpy(self.p2FileHeader.magic, ptypesMagic, len(ptypesMagic))
            self.p2FileHeader.status = 'C'
            self.p2FileHeader.revision = i
            self.p2FileHeader.freeOffset = numMetadata*pagesize

        self.p2FileHeader.status = 'D'
        self.p2LoHeader = self.p2FileHeaders[0]
        self.p2HiHeader = self.p2FileHeaders[1]

    def _mount(self):
        LOG.info("Mounting existing file '{self.fileName}'".format(self=self))
        self.p2HiHeader = self.p2LoHeader = NULL

        cdef int i
        for i in range(numMetadata):
            self.p2FileHeader = self.p2FileHeaders[i] = \
                <CStorageHeader*>self.baseAddress + i*pagesize
            if any(self.p2FileHeader.magic[j] != ptypesMagic[j]
                   for j in range(len(ptypesMagic))
                   ):
                raise Exception('File {self.fileName} is incompatible with '
                                'this version of ptypes!'.format(
                                    self=self)
                                )
            if (self.p2LoHeader == NULL or
                    self.p2LoHeader.revision > self.p2FileHeader.revision):
                self.p2LoHeader = self.p2FileHeader
            if (self.p2HiHeader == NULL or
                    self.p2HiHeader.revision < self.p2FileHeader.revision):
                self.p2HiHeader = self.p2FileHeader

        if self.p2HiHeader.status != 'C':  # roll back
            LOG.info(
                "Latest shutdown was incomplete, restoring previous metadata.")
            self.p2FileHeader = self.p2HiHeader
            self.p2FileHeader[0] = self.p2LoHeader[0]
            if self.p2HiHeader.status != 'C':
                raise Exception("No clean metadata could be found!")
        else:
            LOG.debug("Latest shutdown was clean, using latest metadata.")
            self.p2FileHeader = self.p2LoHeader
            self.p2FileHeader[0] = self.p2HiHeader[0]

        self.p2FileHeader.status = 'D'
        self.p2FileHeader.revision += 1

    def __flush(self):
        self.assertNotClosed()
        BackingFile.flush(self)
        self.p2FileHeader.status = 'C'
        BackingFile.flush(self)

    cpdef flush(self, bint async=False):
        LOG.debug("Flushing {}".format(self))
        self.__flush()
        cdef CStorageHeader *p2FileHeader = self.p2FileHeader
        cdef unsigned long revision = p2FileHeader.revision + 1
        self.p2FileHeader = self.p2FileHeaders[revision % numMetadata]
        self.p2FileHeader[0] = p2FileHeader[0]
        self.p2FileHeader.revision = revision
        self.p2FileHeader.status = 'D'

    cpdef close(self):
        self.assertNotClosed()
        # Need to close the trx first! XXX
        os.close(self.fd)

    def __repr__(self):
        return ("<{self.__class__.__name__} '{self.fileName}'>"
                .format(self=self))


cdef str CProtectedRegion__formatErrorMessage(CProtectedRegion* region,
                                              str message,
                                              int error=0,
                                              fileName=None) except NULL:
    return message.format(
                    baseAddress=hex(<unsigned long>region.baseAddress),
                    length=hex(region.length),
                    error=strerror(error) if error else "",
                    fileName=fileName))


cdef CProtectedRegion* CProtectedRegion_new(BackingFile backingFile
                                            ) except NULL:
    cdef CProtectedRegion *region
    region = <CProtectedRegion *>malloc(sizeof(CProtectedRegion))
    region.length = backingFile.realFileSize
    region.baseAddress = mmap(NULL, region.length, 
                                   PROT_READ, MAP_SHARED, 
                                   backingFile.fd, 0)
    if region.baseAddress == MAP_FAILED:
        #error = errno  # save it, any c-lib call may overwrite it!
        raise RuntimeError(
            CProtectedRegion__formatErrorMessage('Could not map '
                                                 '{fileName}: {error}',
                                                 errno,
                                     fileName=backingFile.fileName)
                                     )
    region.endAddress = region.baseAddress + region.length
    LOG.debug( CProtectedRegion__formatErrorMessage(
            'Mmapped {fileName} memory region {baseAddress}-{length}'))
    if mprotect(region.baseAddress, region.length, PROT_READ):
        raise RuntimeError(CProtectedRegion__formatErrorMessage(
            "Could not protect the memory mapped region "
            "{baseAddress}-{length}: {error}", errno))
    return region


cdef CProtectedRegion_delete(CProtectedRegion* region) except NULL:
    LOG.debug(CProtectedRegion__formatErrorMessage(
                    'Unmapping memory region {baseAddress}-{length}'))
    if munmap(region.baseAddress, region.length):
        raise RuntimeError(CProtectedRegion__formatErrorMessage(
            'Could not unmap {baseAddress}-{length}: {error}', errno))
    region.baseAddress = NULL
    free(region)


cdef CProtectedRegion_flush(CProtectedRegion* region, bint async=0
                            ) except NULL:
    LOG.debug(CProtectedRegion__formatErrorMessage(
                    'Msyncing memory region {baseAddress}-{length}'))
    if msync(self.region.baseAddress, self.region.length,
             MS_ASYNC if async else MS_SYNC):
        raise RuntimeError(CProtectedRegion__formatErrorMessage(
            'Could not sync {baseAddress}-{length}: {error}', errno))


cdef class Trx(object):
    """ An atomically updateable memory region mapped into a file
    """
    def __cinit__(self, BackingFile backingFile):
        self.backingFile = backingFile
        self.region =CProtectedRegion_new(backingFile)

    def __dealloc__(self):
        global currentRegion
        if currentRegion == self.region:
            currentRegion = NULL
        if self.region != NULL:
            CProtectedRegion_delete(self.region)
            self.region = NULL

    def __init__(self, BackingFile backingFile):
        self.resume()

    cdef Trx resume(Trx self):
        global currentRegion, currentTrx
        cdef Trx *oldTrx = currentTrx
        currentTrx = self
        currentRegion = self.region
        return oldTrx

    cdef Trx close(Trx self, type Persistent, bint doCommit):
        LOG.debug("Closing {}".format(self))
        self.trx.assertNotClosed()
        suspects = [o for o in gc.get_referrers(self)
                    if (isinstance(o, Persistent) and
                        o not in [self.__root, self.stringRegistry]
                        )
                    ]
        if suspects:
            LOG.warning('The following proxy objects are probably part of a '
                        'reference cycle: \n{}' .format(suspects)
                        )
        gc.collect()
        suspects = [o for o in gc.get_referrers(self)
                    if (isinstance(o, Persistent) and
                        o not in [self.__root, self.stringRegistry]
                        )
                    ]
        if suspects:
            raise ValueError("Cannot close {} - some proxies are still around:"
                             " {}".format(
                                 self, ' '.join([repr(s) for s in suspects]))
                             )
        self.__flush()

cdef initPageManager():
    cdef sigaction_t action
    action.sa_sigaction = segv_handler

    if sigemptyset(&(action.sa_mask)):
        raise RuntimeError("Could not set signal mask.")

    action.sa_flags = SA_SIGINFO

    if sigaction(SIGSEGV, &action, &originalSigSegAction): 
        raise RuntimeError("Could not install the signal handler for "
                           "segmentation faults.")


cdef void segv_handler(int sig, siginfo_t *si, void *x ) nogil:
    cdef int error
    if (sig != SIGSEGV or si.si_signo != SIGSEGV or 
            si.si_code != SEGV_ACCERR or currentRegion == NULL or
            si.si_addr < currentRegion.baseAddress or
            si.si_addr >= currentRegion.endAddress):
        sigaction(SIGSEGV, &originalSigSegAction, NULL)
        return
    cdef void* pageAddress = <void*>(<size_t>si.si_addr & pageAddressMask)
    if mprotect(pageAddress, pagesize, PROT_READ|PROT_WRITE):
        error = errno
        perror("Could not adjust page protection.")
        sigaction(SIGSEGV, &originalSigSegAction, NULL)
        return
    return



cdef size_t pagesize = getpagesize()
cdef size_t pageAddressMask = ~(pagesize-1)

cdef sigaction_t originalSigSegAction
cdef CProtectedRegion *currentRegion = NULL
cdef Trx currentTrx = None

initPageManager()

# cdef struct CRedoFileHeader:
#     char magic[lengthOfMagic]
# 
#     # offsets to the first trx header and to where the next trx header
#     # probably can be written (just a hint, a shortcut to a trx header
#     # near to the tail, need to verify if it is really unused,
#     # i.e. the length & checksum of the trx header are zeros)
#     Offset o2firstTrx, o2Tail
# 
# cdef class Redo(BackingFile):
#     cdef:
#         CRedoFileHeader       *p2FileHeader
#         CTrxHeader            *p2Tail
# 
#     def __init__(self, str fileName, int numPages=0):
#         BackingFile.__init__(self, fileName, numPages)
#         cdef:
#             MD5_CTX md5Context
#             MD5_checksum checksum
#         self.p2Tail = <CTrxHeader*>(self.baseAddress +
#                                     self.p2FileHeader.o2Tail)
#         while (self.p2Tail.length != 0 and
#                self.p2Tail.length < self.realFileSize
#                ):
#             MD5_Init(&md5Context)
#             MD5_Update(&md5Context, <void*>(self.p2Tail+1), self.p2Tail.length)
#             MD5_Final(checksum, &md5Context, )
#             if memcmp(self.p2Tail.checksum, checksum, sizeof(MD5_checksum)):
#                 break
#             self.p2Tail = <CTrxHeader *>(<void*>self.p2Tail +
#                                          sizeof(CTrxHeader) +
#                                          self.p2Tail.length
#                                          )
# 
#     def _initialize(self):
#         LOG.info("Initializing journal '{self.fileName}'".format(self=self))
#         assert len(ptypesRedoMagic) < lengthOfMagic
#         cdef int j
#         self.p2FileHeader = <CRedoFileHeader*>self.baseAddress
#         for j in range(len(ptypesRedoMagic)):
#             self.p2FileHeader.magic[j] = ptypesRedoMagic[j]
#         self.p2FileHeader.o2Tail = self.p2FileHeader.o2firstTrx = sizeof(
#             CRedoFileHeader)  # numMetadata*PAGESIZE
# 
#     def _mount(self):
#         LOG.info(
#             "Mounting existing journal '{self.fileName}'".format(self=self))
#         self.p2FileHeader = <CRedoFileHeader*>self.baseAddress
#         if any(self.p2FileHeader.magic[j] != ptypesRedoMagic[j]
#                for j in range(len(ptypesRedoMagic))
#                ):
#             raise Exception('File {self.fileName} is incompatible with this'
#                             'version of ptypes!'.format(self=self)
#                             )
# 
#     cpdef close(self):
#         self.flush()
#         self.p2FileHeader.o2Tail = <void*>self.p2Tail - self.baseAddress
#         self.flush()
# 
# cdef struct CTrxHeader:
#     # A transaction starts with a trx header, which is followed by a set of
#     # redo records with the given total length.
#     # It is committed if the checksum is correct (it is filled in after all the
#     # redo records).
#     # We rely on the "sparse file" mechanism of the kernel to initialize this
#     # data structure to zeros.
#     unsigned long length
#     MD5_checksum checksum
# 
# cdef struct CRedoRecordHeader:
#     # A redo record consists of a redo record header followed by a body
#     # The body has the given length and is opaque; it is copied byte-by-byte
#     # to the target offset when the redo is applied.
#     Offset offset
#     unsigned long length
# 
# cdef class Trx(object):
#     cdef:
#         Storage          storage
#         Redo                redo
# #         CRedoFileHeader     *p2FileHeader
# #         CTrxHeader          *p2TrxHeader
#         CRedoRecordHeader   *p2CRedoRecordHeader
#         MD5_CTX             md5Context
# 
#     def __init__(self, Storage storage, Redo redo):
#         self.storage = storage
#         self.redo = redo
#         redo.assertNotClosed()
# #         self.p2FileHeader = redo.p2FileHeader
# 
#         self.p2CRedoRecordHeader = (<CRedoRecordHeader*>
#                                     (<void*>redo.p2Tail +
#                                      sizeof(CRedoRecordHeader)
#                                      )
#                                     )
#         MD5_Init(&self.md5Context)
# 
#     cdef save(self, const void *sourceAddress, unsigned long length):
#         assert self.redo
#         assert self.storage
#         if (<void*>self.p2CRedoRecordHeader +
#                 sizeof(CRedoRecordHeader) +length >= self.redo.endAddress):
#             raise RedoFullException("{0} is full.".format(self.redo.fileName))
#         self.p2CRedoRecordHeader.offset = sourceAddress - \
#             self.storage.baseAddress
#         self.p2CRedoRecordHeader.length = length
#         # validate source range
#         assert sourceAddress > self.storage.baseAddress
#         assert self.p2CRedoRecordHeader.offset + \
#             length < self.storage.realFileSize
# #         cdef Offset newRedoOffset
#         cdef void *redoRecordPayload = <void*>(self.p2CRedoRecordHeader+1)
#         memcpy(redoRecordPayload, sourceAddress, length)
#         MD5_Update(&self.md5Context, <void*>(self.p2CRedoRecordHeader),
#                    sizeof(CRedoRecordHeader) + length)
#         self.p2CRedoRecordHeader = <CRedoRecordHeader*>(redoRecordPayload +
#                                                         length)
# 
#     cdef commit(self, lazy=False):
#         MD5_Final((self.redo.p2Tail.checksum), &self.md5Context, )
#         self.redo.p2Tail.length = (<void*>self.p2CRedoRecordHeader -
#                                    <void*>self.redo.p2Tail)
#         self.redo.p2Tail = <CTrxHeader*>self.p2CRedoRecordHeader
#         self.redo.flush(lazy)
#         self.redo = self.storage = None
