
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

import os

cdef size_t pagesize = getpagesize()
cdef size_t pageAddressMask = ~(pagesize-1)

cdef sigaction_t originalSigSegAction
cdef CProtectedRegion *currentRegion = NULL


cdef initPageManager():
    cdef sigaction_t action
    action.sa_sigaction = segv_handler

    if sigemptyset(&(action.sa_mask)):
        raise RuntimeError("Could not set signal mask.")

    action.sa_flags = SA_SIGINFO

    if sigaction(SIGSEGV, &action, &originalSigSegAction): #SIGSEGV
        raise RuntimeError("Could not install the signal handler for "
                           "segmentation faults.")


cdef CProtectedRegion *CProtectedRegion_setCurrent(CProtectedRegion *region):
    global currentRegion
    cdef CProtectedRegion *oldRegion = currentRegion
    currentRegion = region
    return oldRegion


cdef CProtectedRegion *CProtectedRegion_new(void *baseAddress,
                                            size_t length,) except NULL:
    cdef CProtectedRegion *region = \
                    <CProtectedRegion *>malloc(sizeof(CProtectedRegion))

    region.baseAddress = baseAddress
    region.length = length
    region.endAddress = baseAddress + length
    if mprotect(region.baseAddress, region.length, PROT_NONE):
        raise RuntimeError("Could not protect the memory mapped region.")
    return region


cdef void segv_handler(int sig, siginfo_t *si, void *x ):
    if (sig != SIGSEGV or si.si_signo != SIGSEGV or 
            si.si_code != SEGV_ACCERR or currentRegion == NULL or
            si.si_addr < currentRegion.baseAddress or
            si.si_addr >= currentRegion.endAddress):
        sigaction(SIGSEGV, &originalSigSegAction, NULL)
        return
    cdef void* pageAddress = <void*>(<size_t>si.si_addr & pageAddressMask)
    if mprotect(pageAddress, pagesize, PROT_READ|PROT_WRITE):
        myerr = errno
        perror("Could not adjust page protection.")
        sigaction(SIGSEGV, &originalSigSegAction, NULL)
        return
    return


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
# 
# cdef struct CRedoRecordHeader:
#     # A redo record consists of a redo record header followed by a body
#     # The body has the given length and is opaque; it is copied byte-by-byte
#     # to the target offset when the redo is applied.
#     Offset offset
#     unsigned long length


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

        