from Cython.Shadow import NULL


cdef extern from "sys/mman.h" nogil:
    void *mmap(void *addr, size_t length, int prot, int flags, int fd,
               int offset)
    int munmap(void *addr, size_t length)
    int mprotect(void *addr, size_t len, int prot)
    int msync(void *addr, size_t length, int flags)
    int PROT_READ, PROT_WRITE, PROT_NONE, MS_ASYNC, MS_SYNC
    int MAP_SHARED, MAP_PRIVATE, MAP_FIXED  # flags
    void *MAP_FAILED

cdef extern from "signal.h" nogil:
    enum: SIGSEGV
    enum: SEGV_ACCERR

cdef extern from "unistd.h" nogil:
    int getpagesize()


cdef extern from "avl-tree.h" nogil:
 
    ctypedef struct AVLTree:
        pass
 
    ctypedef struct AVLTreeNode:
        pass
 
    ctypedef struct AVLTreeKey:
        pass
 
    ctypedef struct AVLTreeValue:
        pass
 
    ctypedef enum AVLTreeNodeMatchType:
        AVL_TREE_NODE_EQUAL
        AVL_TREE_NODE_SMALLER
        AVL_TREE_NODE_GREATER

    ctypedef int (*AVLTreeCompareFunc)(AVLTreeValue value1, 
                                       AVLTreeValue value2)

    ctypedef int (*AVLTreeEnumCallBackFunc)(void* context, AVLTreeNode *node)

#     int AVL_TREE_NODE_SMALLER
 
    AVLTree     *avl_tree_new(AVLTreeCompareFunc compare_func)
    void         avl_tree_free(AVLTree *tree)

    AVLTreeNode *avl_tree_insert(AVLTree *tree, AVLTreeKey key,
                                 AVLTreeValue value)

    int          avl_tree_remove(AVLTree *tree, AVLTreeKey key)

    AVLTreeNode *avl_tree_lookup_nearest_node(AVLTree *tree, AVLTreeKey key,
                                              AVLTreeNodeMatchType match_type)

    AVLTreeValue avl_tree_node_value(AVLTreeNode *node)
    AVLTreeKey   avl_tree_node_key(AVLTreeNode *node)

    int          avl_tree_apply(AVLTree *tree,
                                    AVLTreeEnumCallBackFunc callback,
                                    void* context)

from posix.signal cimport sigaction_t, siginfo_t
from posix.signal cimport sigaction, sigemptyset, SA_SIGINFO
from libc.stdio cimport perror
from libc.errno cimport errno
from libc.stdlib cimport malloc, free
from libc.string cimport strerror, memcpy

cdef char *ptypesMagic     = "ptypes-0.6.0"       # Maintained by bumpbersion,
cdef char *ptypesRedoMagic = "redo-ptypes-0.6.0"  # no manual changes please!

cdef extern from "errno.h":
    int errno

# cdef extern from "string.h":
#     char *strerror(int errnum)
#     void *memcpy(void dest, const void src, size_t n)


import os
import logging
from os import SEEK_SET, O_CREAT, O_RDWR
import gc

LOG = logging.getLogger(__name__)

cdef class BackingFile(object):

    def __init__(self, str fileName, size_t fileSize=0):
        self.fileName = fileName
        try:
            self.fd = os.open(self.fileName, os.O_RDWR)
        except OSError:
            self.numPages = (0 if fileSize==0 else 
                             (fileSize-1)/pagesize + 1 + numMetadata)
            LOG.debug("Creating new file '{self.fileName}'".format(self=self))
            assert self.numPages > 0, ('The database cannot have {numPages} '
                                       'pages.'.format(numPages=self.numPages)
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
        self.o2payloadArea = pagesize * numMetadata

        self.adminMapping = AdminMapping(self)
        self.adminMapping.protect(&self.adminMapping.payloadRegion, PROT_NONE)
        if self.isNew:
            self.adminMapping.protect(&self.adminMapping.adminRegion, 
                                      PROT_READ|PROT_WRITE)
            self.adminMapping.initialize()
        else:
            self.adminMapping.protect(&self.adminMapping.adminRegion, PROT_READ)
            self.adminMapping.mount()
        LOG.debug("Highest metadata revision is {0}"
                  .format(self.adminMapping.p2HiHeader.revision))
        LOG.debug("Lowest metadata revision is {0}"
                  .format(self.adminMapping.p2LoHeader.revision))
        LOG.debug("Using metadata revision {0}"
                  .format(self.adminMapping.p2FileHeader.revision))

        self.adminMapping.protect(&self.adminMapping.adminRegion, PROT_NONE)

        if not self.isNew and fileSize > self.realFileSize:
            raise Exception("File {self.fileName} is of size "
                            "{self.realFileSize}, cannot resize it to "
                            "{fileSize}.".format(self=self, fileSize=fileSize)
                            )

    cpdef close(self):
        self.assertNotClosed() method does not exist
        # Need to close the adminMapping first! XXX
        os.close(self.fd)

    def __repr__(self):
        return ("<{self.__class__.__name__} '{self.fileName}'>"
                .format(self=self))


cdef CRegion* findRegion(void *address ) nogil:
    cdef AVLTreeNode *tree_node = \
        avl_tree_lookup_nearest_node(regions, <AVLTreeKey>address, 
                                     AVL_TREE_NODE_SMALLER)
    if tree_node == NULL:
        return NULL

    cdef CRegion* region = <CRegion*>avl_tree_node_value(tree_node)
    if address < region.endAddress:
        return region

    return NULL


cdef int compareAddresses(AVLTreeValue value1, AVLTreeValue value2) nogil:
    if <size_t>value1 > <size_t>value2:
        return 1
    elif <size_t>value1 == <size_t>value2:
        return 0
    else:
        return -1 


cdef class FileMapping(object):

    cdef map(self, CRegion *region, ):
        region.baseAddress = mmap(NULL, self.region.length, 
                                  PROT_READ, MAP_SHARED, 
                                  region.fd, region.o2Base)
        if region.baseAddress == MAP_FAILED:
            #error = errno  # save it, any c-lib call may overwrite it!
            raise RuntimeError(
                self.__formatErrorMessage(region,
                                    'Could not map {fileName}: {error}',
                                    errno,
                                    fileName=self.backingFile.fileName)
                                    )
        region.endAddress = region.baseAddress + region.length

        LOG.debug( self.__formatErrorMessage(region, 
                'Mmapped {fileName} memory region {baseAddress}-{length}', 0,
                self.backingFile.fileName))

    def __cinit__(self, BackingFile backingFile):
        self.backingFile = backingFile

        self.region.fd = self.adminRegion.fd = \
                self.payloadRegion.fd = backingFile.fd

        # Whole file
        self.region.o2Base = 0
        self.region.length = backingFile.realFileSize
        self.map(&self.region)

        # Admin region 
        self.adminRegion.o2Base = 0
        self.adminRegion.length = backingFile.o2payloadArea
        self.adminRegion.baseAddress = self.region.baseAddress

        self.adminRegion.endAddress = \
                self.region.baseAddress + self.adminRegion.length

        # Payload region 
        self.payloadRegion.o2Base = self.adminRegion.length

        self.payloadRegion.length = \
                self.region.length - self.adminRegion.length

        self.payloadRegion.baseAddress = self.adminRegion.endAddress
        self.payloadRegion.endAddress = self.region.endAddress

    def __dealloc__(self):
        if self.region.baseAddress != NULL:
            LOG.debug(self.__formatErrorMessage(&self.region,
                            'Unmapping memory region {baseAddress}-{length}'))
            if munmap(self.region.baseAddress, self.region.length):
                raise RuntimeError(self.__formatErrorMessage(&self.region, 
                    'Could not unmap {baseAddress}-{length}: {error}', errno))
            self.region.baseAddress = self.adminRegion.baseAddress = \
                    self.payloadRegion.baseAddress = NULL

    cdef str __formatErrorMessage(self, CRegion *region, str message, 
                                  int error=0, fileName=None):
        return message.format(
                    baseAddress=hex(<unsigned long>region.baseAddress),
                    length=hex(region.length),
                    error=strerror(error) if error else "",
                    fileName=fileName)


# cdef class AdminMapping(FileMapping):
cdef class AdminMapping(FileMapping):

    cdef protect(self, CRegion *region, int protectionMode):
        if mprotect(region.baseAddress, region.length, protectionMode):
            raise RuntimeError(self.__formatErrorMessage(region,
                "Could not protect the memory mapped region "
                "{baseAddress}-{length}: {error}", errno))

    cdef flush(self, CRegion *region, bint async=0):
        LOG.debug(self.__formatErrorMessage(region,
                        'Msyncing memory region {baseAddress}-{length}'))
        if msync(region.baseAddress, region.length,
                 MS_ASYNC if async else MS_SYNC):
            raise RuntimeError(self.__formatErrorMessage(region,
                'Could not sync {baseAddress}-{length}: {error}', errno))

    cdef initialize(self):
        LOG.info("Initializing new file '{0}'"
                 .format(self.backingFile.fileName))
        assert len(ptypesMagic) < lengthOfMagic

        cdef int i
        for i in range(numMetadata):
            self.p2FileHeader = self.p2FileHeaders[i] = \
                    <CBackingFileHeader*>(self.region.baseAddress + i*pagesize)
            memcpy(self.p2FileHeader.magic, ptypesMagic, len(ptypesMagic))
            self.p2FileHeader.status = 'C'
            self.p2FileHeader.revision = i

        self.p2LoHeader = self.p2FileHeaders[0]
        self.p2HiHeader = self.p2FileHeaders[1]

    cdef mount(self):
        LOG.info("Mounting existing file '{0}'"
                 .format(self.backingFile.fileName))
        self.p2HiHeader = self.p2LoHeader = NULL

        cdef int i
        for i in range(numMetadata):
            self.p2FileHeader = self.p2FileHeaders[i] = \
                <CBackingFileHeader*>(self.region.baseAddress + i*pagesize)
            if any(self.p2FileHeader.magic[j] != ptypesMagic[j]
                   for j in range(len(ptypesMagic))
                   ):
                raise Exception('File {0} is incompatible with '
                                'this version of ptypes!'.format(
                                    self.backingFile.fileName)
                                )
            if (self.p2LoHeader == NULL or
                    self.p2LoHeader.revision > self.p2FileHeader.revision):
                self.p2LoHeader = self.p2FileHeader
            if (self.p2HiHeader == NULL or
                    self.p2HiHeader.revision < self.p2FileHeader.revision):
                self.p2HiHeader = self.p2FileHeader

        if self.p2HiHeader.status == 'C':  # roll back
            LOG.debug("Latest shutdown was clean, using latest metadata.")
            self.p2FileHeader = self.p2LoHeader
            self.p2FileHeader[0] = self.p2HiHeader[0]
        else:
            LOG.info(
                "Latest shutdown was incomplete, restoring previous metadata.")
            self.p2FileHeader = self.p2HiHeader
            self.p2FileHeader[0] = self.p2LoHeader[0]
            if self.p2HiHeader.status != 'C':
                raise Exception("No clean metadata could be found!")

    cdef sync(self, Trx trx, bint doFlush=False):
        cdef:
            CBackingFileHeader *p2OriginalFileHeader = self.p2FileHeader
        if doFlush:
            self.protect(&self.adminRegion, PROT_READ|PROT_WRITE)
            self.p2FileHeader = self.p2FileHeaders[ 
                               p2OriginalFileHeader.revision % numMetadata]
            self.p2FileHeader[0] = p2OriginalFileHeader[0]  # copy the header
            self.p2FileHeader.status = 'D'
            self.p2FileHeader.revision += 1
            # self.p2FileHeader.lastAppliedRedoFileNumber
            # self.p2FileHeader.o2lastAppliedTrx
            self.protect(&self.adminRegion, PROT_NONE)

        self.protect(&self.payloadRegion, PROT_READ|PROT_WRITE)
        trx.updatePayload(self.region.baseAddress)
        self.protect(&self.payloadRegion, PROT_NONE)

        if doFlush:
            self.flush(&self.payloadRegion)
            self.protect(&self.adminRegion, PROT_READ|PROT_WRITE)
            self.p2FileHeader.status = 'C'
            self.protect(&self.adminRegion, PROT_NONE)
            self.flush(&self.adminRegion)

cdef class Trx(FileMapping):
    """ An atomically updateable memory region mapped into a file
    """
    def __cinit__(self, BackingFile backingFile):
        self.payloadRegion.dirtyPages = avl_tree_new(compareAddresses)
        if NULL == avl_tree_insert(regions, 
                                   <AVLTreeKey>self.payloadRegion.baseAddress, 
                                   <AVLTreeValue>&self.payloadRegion):
            raise MemoryError()


    def __dealloc__(self):
        avl_tree_remove(regions, <AVLTreeKey>self.region.baseAddress)
        avl_tree_free(self.payloadRegion.dirtyPages)
        self.payloadRegion.dirtyPages = NULL


    cdef Trx close(Trx self, type Persistent, bint doCommit):
        LOG.debug("Closing {}".format(self))
        self.assertNotClosed()
        suspects = [o for o in gc.get_referrers(self)
                    if isinstance(o, Persistent)
                    ]
        if suspects:
            LOG.warning('The following proxy objects are probably part of a '
                        'reference cycle: \n{}' .format(suspects)
                        )
        gc.collect()
        suspects = [o for o in gc.get_referrers(self)
                    if isinstance(o, Persistent)
                    ]
        if suspects:
            raise ValueError("Cannot close {} - some proxies are still around:"
                             " {}".format(
                                 self, ' '.join([repr(s) for s in suspects]))
                             )
        self.backingFile.adminMapping.sync(self, doFlush=True)

    cdef updatePayload(self, void *targetRegionBaseAddress):
        avl_tree_apply(self.payloadRegion.dirtyPages, copyPage, 
                       targetRegionBaseAddress)


cdef int copyPage(void *targetRegionBaseAddress, AVLTreeNode *node) nogil:
    cdef:
        Offset offset = <Offset>avl_tree_node_key(node)
        void *source = <void*>avl_tree_node_value(node)
        void *destination = targetRegionBaseAddress + offset 
    memcpy(destination, source, pagesize)
    return 1

cdef void segv_handler(int sig, siginfo_t *si, void *x ) nogil:
    cdef:
        int      error
        CRegion* payloadRegion
        void*    pageAddress
        Offset   pageOffset   # offset of the page within the file 

    if (sig == SIGSEGV and si.si_signo == SIGSEGV and 
            si.si_code == SEGV_ACCERR ):
        payloadRegion = findRegion(si.si_addr)
        if payloadRegion != NULL:
            pageAddress = <void*>(<size_t>si.si_addr & pageAddressMask)
#             if mprotect(pageAddress, pagesize, PROT_READ|PROT_WRITE):
            pageOffset = pageAddress - payloadRegion.baseAddress + \
                    payloadRegion.o2Base
            if MAP_FAILED == mmap(pageAddress, pagesize, PROT_READ|PROT_WRITE, 
                                  MAP_PRIVATE|MAP_FIXED, 
                                  payloadRegion.fd, pageOffset):
                error = errno
                perror("Could not remap the page.")
            else:
                if NULL == avl_tree_insert(payloadRegion.dirtyPages, 
                                           <AVLTreeKey>pageOffset, 
                                           <AVLTreeValue>pageAddress):
                    perror("Cannot insert the touched memory page into the "
                           "dirty list: out of memory.")
                else:
                    return
    sigaction(SIGSEGV, &originalSigSegAction, NULL)


cdef initPageManager():
    global regions
    regions = avl_tree_new(compareAddresses)

    cdef sigaction_t action
    action.sa_sigaction = segv_handler

    if sigemptyset(&(action.sa_mask)):
        raise RuntimeError("Could not set signal mask.")

    action.sa_flags = SA_SIGINFO

    if sigaction(SIGSEGV, &action, &originalSigSegAction): 
        raise RuntimeError("Could not install the signal handler for "
                           "segmentation faults.")



cdef size_t pagesize = getpagesize()
cdef size_t pageAddressMask = ~(pagesize-1)

cdef sigaction_t originalSigSegAction

cdef AVLTree *regions 

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
#     def initialize(self):
#         LOG.info("Initializing journal '{self.fileName}'".format(self=self))
#         assert len(ptypesRedoMagic) < lengthOfMagic
#         cdef int j
#         self.p2FileHeader = <CRedoFileHeader*>self.baseAddress
#         for j in range(len(ptypesRedoMagic)):
#             self.p2FileHeader.magic[j] = ptypesRedoMagic[j]
#         self.p2FileHeader.o2Tail = self.p2FileHeader.o2firstTrx = sizeof(
#             CRedoFileHeader)  # numMetadata*PAGESIZE
# 
#     def mount(self):
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
