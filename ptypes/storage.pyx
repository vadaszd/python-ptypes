# cython: profile=False


from cpython.version cimport PY_MAJOR_VERSION
from libc.string cimport memcpy, memcmp, memset
from md5 cimport MD5_checksum, MD5_CTX, MD5_Init, MD5_Update, MD5_Final

from math import pow, log as logarithm
from types import ModuleType
from collections import namedtuple
from time import strptime, mktime
import os
import threading
import textwrap
import inspect
from codecs import decode
from warnings import warn

from .compat import pickle

import logging
LOG = logging.getLogger(__name__)

cdef class PList


class DbFullException(Exception):
    pass


class RedoFullException(Exception):
    pass

cdef class Persistent(object):
    """ Base class for all the proxy classes for persistent objects.
    """

    def __repr__(self):
        return ("<persistent {0} object @offset {1}>"
                .format(self.ptype.__name__, hex(self.offset))
                )

    def __hash__(self, ):
        return self.offset

    def __richcmp__(Persistent self, other, int op):
        return bool(self.richcmp(other, op))

    property id:
        """ Read-only property giving a tuple uniquely identifying the object.

        The returned value is valid within the current transaction only.
        """

        def __get__(self):
            return id(self.trx), self.offset

    def isSameAs(Persistent self, Persistent other):
        """ Compare the identity of :class:`Persistent` instances.

        Note that the ``is`` operator compares the identity of the proxy
        objects, not that of the persistent objects they refer to.

        .. py:function:: isSameAs(self, other)

        :param Persistent self: proxy for a persistent object
        :param Persistent other: proxy for another persistent object
        :return: ``True`` if ``self`` refers to the same persistent object as
                    ``other``, otherwise ``False``.
        """
        return self.offset == other.offset and self.trx is other.trx

    cdef int richcmp(Persistent self, other, int op) except? -123:
        raise NotImplementedError()

    cdef store(Persistent self, void *target):
        """ Store self to target.

            Stores by reference or by value (as the type of self dictates).
        """
        raise NotImplementedError()

    cdef revive(Persistent p):
        pass

# ================ Assignment By Value ================

cdef Offset resolveNoOp(PersistentMeta ptype, Trx trx, Offset offset
                        ) except -1:
    return offset

cdef class AssignedByValue(Persistent):
    # p2InternalStructure points at a persistent object embedded inside
    # another persistent object

    cdef store(AssignedByValue self, void *target):
        # copies bytes from the value
        memcpy(target, self.p2InternalStructure, self.ptype.assignmentSize)

    # Works only with persistent values. Can be specialized in derived
    # classes for specific types. In the overrider call this if
    # other is persistent, otherwise use the special code
    cdef int richcmp(AssignedByValue self, other, int op) except? -123:
        assert other is not None
        cdef Persistent pother = <Persistent?>other
        cdef int doesDiffer
        if self.ptype == pother.ptype:
            doesDiffer = memcmp(self.p2InternalStructure,
                                pother.p2InternalStructure,
                                self.ptype.assignmentSize)
        else:
            doesDiffer = 1
        if op==2:
            return doesDiffer == 0
        if op==3:
            return doesDiffer != 0
        raise TypeError('{0} does not define a sort order!'.format(self.ptype))

# ================ Assignment By Reference ================

cdef Offset resolveReference(PersistentMeta ptype, Trx trx, Offset offset
                             ) except -1:
    return (<Offset*>trx.offset2Address(offset))[0]

cdef class AssignedByReference(Persistent):
    # p2InternalStructure points at a stand-alone object on the heap
    cdef store(AssignedByReference self, void *target):
        # store the offset to the value
        (<Offset*>target)[0] = self.trx.address2Offset(self.p2InternalStructure)

    # works only with persistent values. Can be specialized in derived
    # classes for specific types.
    # In the overrider call this if other is persistent, otherwise use the
    # special code
    cdef int richcmp(AssignedByReference self, other, int op) except? -123:
        cdef:
            Persistent pother
            int doesDiffer
        if other is None:
            doesDiffer = 1
        else:
            pother = <Persistent?>other
            if self.ptype == pother.ptype:
                doesDiffer = self.offset != other.offset
            else:
                doesDiffer = 1
        if op==2:
            return doesDiffer == 0
        if op==3:
            return doesDiffer != 0
        raise TypeError('{0} does not define a sort order!'.format(self.ptype))

# ================ PersistentMeta ================

cdef class PersistentMeta(type):
    """ Abstract base meta class for all persistent types.
    """
    @classmethod
    def _typedef(PersistentMeta meta, Storage storage, str className,
                 type proxyClass, *args):
        """ Create and initialize a new persistent type.

        This is a non-public classmethod of :class:`PersistentMeta` and
        derived classes.

        :param meta: This type object must be the one representing
                :class:`PersistentMeta` or another class derived from
                it. (This parameter is normally filled in with the meta-class
                of the class the method is invoked on.) The new persistent
                type is created using this type object as its meta-class.

        @param storage:
        @param className: This will be the name of the new type.
        @param proxyClass: The new persistent type will be a
                subclass of this class.

        @return: A properly initialized PersistentMeta instance
                representing the newly created persistent type.
        """
        cdef PersistentMeta ptype = meta.__new__(meta, className,
                                                 (proxyClass,),
                                                 dict(__metaclass__=meta)
                                                 )
        meta.__init__(ptype, storage, className, proxyClass, *args)
        LOG.debug('Created {ptype} from meta-class {meta} using proxy'
                  ' {proxyClass} with arguments {args}'
                  .format(ptype=ptype, meta=meta, proxyClass=proxyClass,
                          args=args)
                  )
        return ptype

    # This method is called to initialize an instance of this meta-class
    # when a new persistent type has just been created
    def __init__(PersistentMeta ptype, Storage storage, str className,
                 type proxyClass, int allocationSize):
        """ Initialize the ptype
        """
        super(PersistentMeta, ptype).__init__(className, (), {})
        ptype.__name__   = className
        ptype.storage = storage
        ptype.proxyClass = proxyClass
        ptype.allocationSize = allocationSize
        if ptype.isAssignedByValue():
            ptype.assignmentSize = allocationSize
            ptype.resolve = resolveNoOp
        else:
            ptype.assignmentSize = sizeof(Offset)
            ptype.resolve = resolveReference

        if not ptype.__name__.startswith('__'):
            storage.registerType(ptype)

    # This method is executed when the function call operator is applied to an
    # instance of this meta-class (which in fact represents a persistent type),
    # here referred to as "ptype"
    def __call__(PersistentMeta ptype, *args, **kwargs):
        """ Create an instance of the ptype.
        """
        if ptype.isAssignedByValue():
            raise TypeError(
                '{ptype} exhibits store-by-value semantics and therefore can '
                'only be instantiated inside a container (e.g. in Structure)'
                .format(ptype=ptype))
        # always by ref
        cdef Persistent self = ptype.createProxy(ptype.storage.trx, 
                                                 allocateStorage(ptype))
        ptype.proxyClass.__init__(self, *args, **kwargs)
        return self

    cdef Persistent createProxy(PersistentMeta ptype, Trx trx, Offset offset):
        cdef Persistent self
        if offset:
            self = ptype.__new__(ptype)
            self.p2InternalStructure =  trx.offset2Address(offset)
            self.ptype = ptype
            self.trx = trx
            self.offset = offset
#             LOG.debug('createProxy: {0} {1} ==> {2}'
#                        .format(ptype.proxyClass, offset, repr(self)))
            self.revive()
            return self
        else:
            return None

    def reduce(self):
        return '_typedef', self.__name__, self.__class__, self.proxyClass

    cdef assign(PersistentMeta ptype, Trx targetTrx, void *target, source, ):
        """ Assign source to target converting to persistent if needed.

            If ``source`` is a persistent type then it must be an instance of
            the type represented by ``ptype`` in ``targetTrx``. If it is a volatile Python value
            and the type represented by ``ptype`` is assigned by value, then
            the assignment is performed via the ``contents`` descriptor of the
            type. For types assigned by reference a new instance of the type is
            created in ``targetTrx`` and ``source`` is passed to the constructor, unless it is
            ``None``, in which case the reference is set to the persistent
            representation of ``None``.
        """
        cdef Persistent self
        if isinstance(source, Persistent):
            ptype.assertType(source)
            source.assertInTrx(targetTrx)
            (<Persistent>source).store(target)
        elif ptype.isAssignedByValue():
            ptype.resolveAndCreateProxyFA(targetTrx, target).contents = source
        elif source is None:
            (<Offset*>target)[0] = 0
        else:
            self = <Persistent>ptype(source)
            self.assertInTrx(targetTrx)
            self.store(target)

    cdef void clear(PersistentMeta ptype, Offset o2Target):
        memset(ptype.storage.trx.offset2Address(o2Target), 0, ptype.assignmentSize)

    cdef int isAssignedByValue(PersistentMeta ptype) except? -123:
        cdef:
            bint isByValue = issubclass(ptype.proxyClass, AssignedByValue)
            bint raiseTypeError=False
        if isByValue:
            raiseTypeError = issubclass(ptype.proxyClass, AssignedByReference)
        else:
            raiseTypeError = not issubclass(
                ptype.proxyClass, AssignedByReference)
        if raiseTypeError:
            raise TypeError("The proxyClass {0} must be a subclass of  either "
                            "'AssignedByValue' or 'AssignedByReference'."
                            .format(ptype.proxyClass))
        return isByValue

    cdef assertType(PersistentMeta ptype, Persistent persistent):
        if persistent:
            if persistent.trx is not ptype.storage.trx:
                raise ValueError(
                    "Expected a persistent object in {0}, not in {1}!"
                    .format(ptype.storage.trx, persistent.trx)
                )
            if not issubclass(persistent.ptype, ptype):
                raise TypeError(
                    "Expected {0}, found {1}".format(ptype, persistent.ptype))

    def __repr__(ptype):
        return "<persistent class '{0}'>".format(ptype.__name__)


# ================ Type Descriptor ================

cdef class TypeDescriptor(object):
    minNumberOfParameters=None
    maxNumberOfParameters=None

    def __init__(TypeDescriptor self, str className=None):
        if className is None:
            className = self.__class__.__name__
        self.className = className
        self.typeParameters = tuple()

    def __getitem__(TypeDescriptor self, typeParameters):
        if not isinstance(typeParameters, tuple):
            typeParameters = typeParameters,
        if self.typeParameters:
            raise ValueError("The parameters of type {self.className} are "
                             "already set to {self.typeParameters}"
                             .format(self=self))
        self.verifyTypeParameters(typeParameters)
        self.typeParameters = typeParameters
        return self

    def verifyTypeParameters(self, tuple typeParameters):
        if self.minNumberOfParameters is None and typeParameters:
            raise TypeError("The type {self.className} does not accept "
                            "parameters!".format(self=self))

        if self.minNumberOfParameters and (len(typeParameters) <
                                           self.minNumberOfParameters):
            raise TypeError("Type {self.className} must have at least "
                            "{self.minNumberOfParameters} parameter(s), "
                            "found {typeParameters}".format(
                                self=self, typeParameters=typeParameters)
                            )
        if self.maxNumberOfParameters and (len(typeParameters) >
                                           self.maxNumberOfParameters):
            raise TypeError("Type {self.className} must have at most "
                            "{self.maxNumberOfParameters} parameter(s), "
                            "found {typeParameters}".format(
                                self=self, typeParameters=typeParameters)
                            )

# ================ Int  ================

cdef class IntMeta(PersistentMeta):

    def __init__(IntMeta ptype,
                 Storage storage,
                 str className,
                 type proxyClass,
                 ):
        assert issubclass(proxyClass, PInt), proxyClass
        PersistentMeta.__init__(ptype, storage, className, proxyClass,
                                sizeof(long))

cdef class PInt(AssignedByValue):

    cdef inline long *getP2IS(self):
        return <long *>self.p2InternalStructure

    def __str__(self):
        return str(self.getP2IS()[0])

    def __repr__(self):
        return ("<persistent {0} object '{1}' @offset {2}>"
                .format(self.ptype.__name__, self.getP2IS()[0],
                        hex(self.offset)))

    property contents:
        def __get__(self):
            return self.getP2IS()[0]

        def __set__(self, long value):
            self.getP2IS()[0] = value

    # The offset is not OK here: it must match that of the volatile object!
    def __hash__(self, ):
        return hash(self.getP2IS()[0])

    cdef int richcmp(PInt self, other, int op) except? -123:
        cdef long otherValue
        if isinstance(other, PInt):
            otherValue = (<PInt> other).getP2IS()[0]
        else:
            if isinstance(other, int):
                otherValue = <long?>other
            else:
                if op==2:
                    return False  # self == other
                if op==3:
                    return True  # self != other
                raise TypeError(
                    '{0} does not define a sort order for {1!r}!'
                    .format(self.ptype, other)
                )
        if op==0:
            return self.getP2IS()[0] <  otherValue  # self  < other
        if op==1:
            return self.getP2IS()[0] <= otherValue  # self <= other
        if op==2:
            return self.getP2IS()[0] == otherValue  # self == other
        if op==3:
            return self.getP2IS()[0] != otherValue  # self != other
        if op==4:
            return self.getP2IS()[0] >  otherValue  # self  > other
        if op==5:
            return self.getP2IS()[0] >= otherValue  # self >= other
        assert False, "Unknown operation code '{0}".format(op)

    cpdef inc(self):
        self.getP2IS()[0] += 1

    cpdef add(self, long value):
        self.getP2IS()[0] += value

    cpdef setBit(self, int numberOfBit):
        self.getP2IS()[0] |= 1 << numberOfBit

    cpdef clearBit(self, int numberOfBit):
        self.getP2IS()[0] &= ~(1 << numberOfBit)

    cpdef int testBit(self, int numberOfBit):
        return self.getP2IS()[0] & (1 << numberOfBit)

cdef class Int(TypeDescriptor):
    meta = IntMeta
    proxyClass = PInt

# ================ Float  ================

cdef class FloatMeta(PersistentMeta):

    def __init__(self,
                 Storage storage,
                 className,
                 proxyClass=None,
                 ):
        if proxyClass is None:
            proxyClass = PFloat
        assert issubclass(proxyClass, PFloat), proxyClass
        PersistentMeta.__init__(
            self, storage, className, proxyClass, sizeof(double))


cdef class PFloat(AssignedByValue):

    cdef inline double *getP2IS(self):
        return <double *>self.p2InternalStructure

    def __str__(self):
        return str(self.getP2IS()[0])

    def __repr__(self):
        return ("<persistent {0} object '{1}' @offset {2}>"
                .format(self.ptype.__name__, self.getP2IS()[0],
                        hex(self.offset)))

    property contents:
        def __get__(self):
            return self.getP2IS()[0]

        def __set__(self, double value):
            self.getP2IS()[0] = value

    # The offset is not OK here: it must match that of the volatile object!
    def __hash__(self, ):
        return hash(self.getP2IS()[0])

    cdef int richcmp(PFloat self, other, int op) except? -123:
        cdef double otherValue
        if isinstance(other, PFloat):
            otherValue = (<PFloat> other).getP2IS()[0]
        else:
            if isinstance(other, float):
                otherValue = <double?>other
            else:
                if op==2:
                    return False  # self == other
                if op==3:
                    return True  # self != other
                raise TypeError(
                    '{0} does not define a sort order for {1!r}!'
                    .format(self.ptype, other))
        if op==0:
            return self.getP2IS()[0] <  otherValue  # self  < other
        if op==1:
            return self.getP2IS()[0] <= otherValue  # self <= other
        if op==2:
            return self.getP2IS()[0] == otherValue  # self == other
        if op==3:
            return self.getP2IS()[0] != otherValue  # self != other
        if op==4:
            return self.getP2IS()[0] >  otherValue  # self  > other
        if op==5:
            return self.getP2IS()[0] >= otherValue  # self >= other
        assert False, "Unknown operation code '{0}".format(op)

    cpdef add(self, double value):
        self.getP2IS()[0] += value

cdef class Float(TypeDescriptor):
    meta = FloatMeta
    proxyClass = PFloat

# ================ ByteString ================

cdef class ByteStringMeta(PersistentMeta):

    def __call__(ByteStringMeta ptype, bytes volatileByteString):
        """ Create an instance of the type ptype represents.
        """
        cdef:
            int size = len(volatileByteString)

            PByteString self = \
                ptype.createProxy(ptype.storage.trx,
                                  ptype.storage.allocate(sizeof(int) + size))

        (<int*>self.p2InternalStructure)[0] = size
        memcpy(self.getCharPtr(), <char*>volatileByteString, size)
        return self

    def __init__(ByteStringMeta ptype,
                 Storage storage,
                 className,
                 proxyClass=None,
                 ):
        if proxyClass is None:
            proxyClass = PByteString
        assert issubclass(proxyClass, PByteString), proxyClass
        # allocationSize is not used, no need to initialize it
        PersistentMeta.__init__(ptype, storage, className, proxyClass, 0)


cdef class PByteString(AssignedByReference):

    def __str__(self):
        """ Return the contained string.

            In Python2, a the byte string persisted is returned.

            In Python3, using this method is a sick idea, because it has to
            convert the bytes string to a unicode string, without knowing the
            actual meaning of the bytes. As the least painful solution, the
            bytes object is decoded using the  latin-1 (a.k.a. iso-8859-1)
            codec, as this maps each byte value in the 0x0-0xff range to a
            valid unicode code point (namely to the one having the same ordinal
            as the value of the byte), so at least we avoid exceptions during
            decoding.
        """
        if PY_MAJOR_VERSION < 3:
            return self.getByteString()
        else:
            warn("Converting a byte string to unicode string is usually a bad "
                 "idea (will use the latin_1 codec for now).",
                 BytesWarning,
                 stacklevel=2)
            return decode(self.getByteString(), 'latin_1')

    def __repr__(self):
        if PY_MAJOR_VERSION < 3:
            s = self.getByteString()
        else:
            s = decode(self.getByteString(), 'latin_1')
        return ("<persistent {0} object '{1}' @offset {2}>".
                format(self.ptype.__name__, s, hex(self.offset))
                )

    property contents:
        def __get__(self):
            return self.getByteString()

    # The offset is not OK here: it must match that of the volatile object!
    def __hash__(self, ):
        return hash(self.getByteString())

    cdef int richcmp(PByteString self, other, int op) except? -123:
        cdef:
            char *selfValue
            char *otherValue
            bytes otherValueAsByteString
            int otherSize, doesDiffer
        selfValue = self.getCharPtr()
        if isinstance(other, PByteString):
            otherSize  = (<PByteString> other).getSize()
            otherValue = (<PByteString> other).getCharPtr()
        else:
            try:
                otherValueAsByteString = other
            except TypeError:
                if op==2:
                    return False  # self == other
                if op==3:
                    return True  # self != other
                raise TypeError(
                    '{0} does not define a sort order for {1!r}!'
                    .format(self.ptype, other)
                )
            else:
                otherSize  = len(otherValueAsByteString)
                otherValue = <char*>otherValueAsByteString
        doesDiffer = memcmp(
            selfValue, <char*>otherValue, min(self.getSize(), otherSize))
        if not doesDiffer:
            doesDiffer =  self.getSize() - otherSize
        if op==0:
            return doesDiffer <  0  # self  < other
        if op==1:
            return doesDiffer <= 0  # self <= other
        if op==2:
            return doesDiffer == 0  # self == other
        if op==3:
            return doesDiffer != 0  # self != other
        if op==4:
            return doesDiffer >  0  # self  > other
        if op==5:
            return doesDiffer >= 0  # self >= other
        assert False, "Unknown operation code '{0}".format(op)

cdef class __ByteString(TypeDescriptor):
    meta = ByteStringMeta
    proxyClass = PByteString


# ================ HashEntry ================
cdef:
    struct CHashTable:
        unsigned long _capacity, _used,
        Offset        _mask, o2EntryTable

cdef class HashEntryMeta(PersistentMeta):
    def __init__(self,
                 Storage          storage,
                 str              className,
                 type             proxyClass,
                 PersistentMeta   keyClass,
                 PersistentMeta   valueClass=None,
                 ):
        assert issubclass(proxyClass, PHashEntry), proxyClass
        self.o2Key   = sizeof(CHashEntry)
        self.o2Value = self.o2Key + keyClass.assignmentSize
        PersistentMeta.__init__(self, storage, className, proxyClass,
                                self.o2Value +
                                (valueClass.assignmentSize if valueClass
                                 else 0)
                                )
        self.keyClass   = keyClass
        self.valueClass = valueClass
        # do these 2 have the same storage as the entrymeta?

    def reduce(self):
        assert False, ("The name of HashEntryMeta instances must start with "
                       "'__' in order to prevent pickling them!")


cdef class PHashEntry(AssignedByValue):
    pass

# ================ HashTable ================

cdef class HashTableMeta(PersistentMeta):

    @classmethod
    def _typedef(PersistentMeta meta, Storage storage, str className,
                 type proxyClass, PersistentMeta keyClass,
                 PersistentMeta valueClass=None):
        if keyClass is None:
            raise TypeError("The type parameter specifying the type of keys "
                            "cannot be {0}" .format(keyClass)
                            )
        cdef:
            str entryName =  (
                ('__{keyClass.__name__}And{valueClass.__name__}AsHashEntry'
                 .format(keyClass=keyClass, valueClass=valueClass)
                 ) if valueClass else (
                    '__{keyClass.__name__}AsHashEntry'
                    .format(keyClass=keyClass)
                )
            )
            PersistentMeta entryClass = HashEntryMeta._typedef(storage,
                                                               entryName,
                                                               PHashEntry,
                                                               keyClass,
                                                               valueClass)

        return super(HashTableMeta, meta)._typedef(storage, className,
                                                   proxyClass, entryClass)

    def __init__(self,
                 Storage       storage,
                 str              className,
                 type             proxyClass,
                 HashEntryMeta    hashEntryClass
                 ):
        assert issubclass(proxyClass, PHashTable), proxyClass
        PersistentMeta.__init__(
            self, storage, className, proxyClass, sizeof(CHashTable))
        self.hashEntryClass =  hashEntryClass

    def reduce(self):
        return ('_typedef', self.__name__, self.__class__, self.proxyClass,
                ('PersistentMeta',
                 None if self.hashEntryClass.keyClass is None
                 else self.hashEntryClass.keyClass.__name__),
                ('PersistentMeta',
                 None if self.hashEntryClass.valueClass is None
                 else self.hashEntryClass.valueClass.__name__),
                )


cdef class PHashTable(AssignedByReference):

    cdef revive(self):
        self.hashEntryClass = (<HashTableMeta>self.ptype).hashEntryClass
        self.keyClass = self.hashEntryClass.keyClass
        self.valueClass =  self.hashEntryClass.valueClass
        self.o2Key =  self.hashEntryClass.o2Key
        self.o2Value =  self.hashEntryClass.o2Value

    def __init__(PHashTable self, unsigned long size, ):
        assert size > 0, 'The size of a HashTable cannot be {size}.'.format(
            size=size)
        actualSize = size*3/2
        actualSize = int(pow(2, int(logarithm(actualSize)/logarithm(2))+1))
        self.getP2IS()._capacity = 9*actualSize/10
        self.getP2IS()._mask = actualSize-1
        self.getP2IS()._used = 0
        cdef unsigned long hashTableSize = (actualSize *
                                            self.hashEntryClass.assignmentSize)
        self.getP2IS().o2EntryTable = self.allocate(hashTableSize)
        memset(self.trx.offset2Address(self.getP2IS().o2EntryTable),
               0, hashTableSize)
        LOG.debug("Created new HashTable  {4} of type '{0}', "
                  "requested_size={1} actual size={2} allowed capacity={3}."
                  .format(self.ptype.__name__, size, actualSize,
                          self.getP2IS()._capacity, self)
                  )

    cdef CHashEntry* _findEntry(self, object key) except NULL:
        cdef unsigned long i, perturb, h
        h = <unsigned long>hash(key)
        i = h & self.getP2IS()._mask
        perturb = h
        cdef:
            CHashEntry* p2Entry = self.getP2Entry(i)
            Persistent foundKey
        while True:
            if not p2Entry.isUsed:
                break
            foundKey = self.getKey(p2Entry)
            if foundKey is None:
                if key is None:
                    break
            else:
                if foundKey.richcmp(key, 2):
                    break
            perturb >>= 5
            i = (i << 2) + i + perturb + 1
            p2Entry = self.getP2Entry(i & self.getP2IS()._mask)
        return p2Entry

    def __getitem__(self, key):
        """ Get they value associated with key.

            @return: the persistent object associated with the key as value

            If the value class of the hash table is None (i.e. applying the
            operation on a set), then the persistent version of the passed in
            key is returned.

            @raise KeyError: the key is unknown
        """
        cdef CHashEntry* p2Entry = self._findEntry(key)
        if not p2Entry.isUsed:
            self.missing(p2Entry, key)
        if self.hashEntryClass.valueClass:
            return self.getValue(p2Entry)
        else:
            return self.getKey(p2Entry)

    cdef missing(self, CHashEntry* p2Entry, key):
        raise KeyError(key)

    def __setitem__(self, key, value):
        """ Set they value associated with key

            If the value class of the hash table is None (i.e. applying the
            operation on a set), then value is silently ignored.
        """
        cdef CHashEntry* p2Entry = self._findEntry(key)
        self.setKey(p2Entry, key)
        if self.hashEntryClass.valueClass:
            self.setValue(p2Entry, value)

    cpdef Persistent get(self, object key, value=None):
        """ Return the matching persistent version of a volatile key.

            If the hash table does not have a matching persistent key, then
            the volatile key is persisted according to the assignemnt rules of
            the key class. If the key is persisted in the current invocation,
            then the optional value is also associated to the key, provided the
            value class of the hash table is not ``None`` (i.e. the hash table
            on which ``get()`` was invoked is a dictionary). If the value class
            is ``None`` (the hash table is a set), then the value is always
            silently ignored. If the hash table already contained a matching
            persistent key before the invocation, then the value associated
            with the key is not altered.

            @return: The matching persistent key.
        """
        cdef CHashEntry* p2Entry = self._findEntry(key)
        if not p2Entry.isUsed:
            self.setKey(p2Entry, key)
            if self.hashEntryClass.valueClass:
                self.setValue(p2Entry, value)
        return self.getKey(p2Entry)

    def iterkeys(self):
        cdef:
            unsigned long i
            CHashEntry* p2Entry
        for i in range(0, self.getP2IS()._mask+1):
            p2Entry = self.getP2Entry(i)
            if p2Entry.isUsed:
                yield self.getKey(p2Entry)

    def itervalues(self):
        cdef:
            unsigned long i
            CHashEntry* p2Entry
        if self.hashEntryClass.valueClass:
            for i in range(0, self.getP2IS()._mask+1):
                p2Entry = self.getP2Entry(i)
                if p2Entry.isUsed:
                    yield self.getValue(p2Entry)
        else:
            raise TypeError('Cannot iterate over the values: no value class '
                            'is defined. (Is this not a Set?)')

    def iteritems(self):
        cdef:
            unsigned long i
            CHashEntry* p2Entry
        if self.hashEntryClass.valueClass:
            for i in range(0, self.getP2IS()._mask+1):
                p2Entry = self.getP2Entry(i)
                if p2Entry.isUsed:
                    yield (self.getKey(p2Entry), self.getValue(p2Entry))
        else:
            raise TypeError('Cannot iterate over the items: no value class '
                            'is defined. (Is this not a Set?)')

    cdef incrementUsed(self):
        if self.getP2IS()._used >= self.getP2IS()._capacity:
            raise DbFullException("HashTable of type '{0}' is full, current "
                                  "capacity is {1}."
                                  .format(self.ptype.__name__,
                                          self.getP2IS()._capacity)
                                  )
        self.getP2IS()._used += 1

    property numberOfUsedEntries:
        def __get__(self):
            return self.getP2IS()._used

    property capacity:
        def __get__(self):
            return self.getP2IS()._capacity

cdef class PDefaultHashTable(PHashTable):

    cdef missing(self, CHashEntry* p2Entry, key):
        self.incrementUsed()
        p2Entry.isUsed = 1
        self.setKey(p2Entry, key)
        value = self.hashEntryClass.valueClass()
        self.setValue(p2Entry, value)


# ================  Set ================
cdef class Set(TypeDescriptor):
    meta = HashTableMeta
    proxyClass = PHashTable
    minNumberOfParameters=1
    maxNumberOfParameters=1


# ================  Dictionary ================
cdef class Dict(TypeDescriptor):
    meta = HashTableMeta
    proxyClass = PHashTable
    minNumberOfParameters=2
    maxNumberOfParameters=2


cdef class DefaultDict(Dict):
    proxyClass = PDefaultHashTable


# ================ List ================
cdef class ListMeta(PersistentMeta):

    @classmethod
    def _typedef(PersistentMeta meta, Storage storage, str className,
                 type proxyClass, PersistentMeta valueClass):
        if valueClass is None:
            raise TypeError("The type parameter specifying the type of list "
                            "elements cannot be None.")
        return super(ListMeta, meta)._typedef(storage, className, proxyClass,
                                              valueClass)

    def __init__(self,
                 Storage       storage,
                 str              className,
                 type             proxyClass,
                 PersistentMeta   valueClass,
                 ):
        assert issubclass(proxyClass, PList), proxyClass
        PersistentMeta.__init__(
            self, storage, className, proxyClass, sizeof(CList))
        self.valueClass  = valueClass
        self.o2Value = sizeof(CListEntry)

    def reduce(self):
        return ('_typedef', self.__name__, self.__class__, self.proxyClass,
                ('PersistentMeta', self.valueClass.__name__),
                )


cdef class PList(AssignedByReference):

    def __init__(self):
        self.getP2IS().o2FirstEntry = self.getP2IS().o2LastEntry = 0

    cdef CListEntry *newEntry(self, value, Offset* o2NewEntry):
        cdef PersistentMeta valueClass = (<ListMeta>(self.ptype)).valueClass
        o2NewEntry[0] = self.allocate(
            sizeof(CListEntry)  + valueClass.assignmentSize)
        cdef CListEntry *p2NewEntry = (
                       <CListEntry *>self.trx.offset2Address(o2NewEntry[0]))
        valueClass.assign(self.trx, (<void*>p2NewEntry) +
                                    (<ListMeta>(self.ptype)).o2Value,
                          value
                          )
        return p2NewEntry

    cpdef insert(PList self, object value):
        cdef:
            Offset o2NewEntry
            CListEntry   *p2NewEntry = self.newEntry(value, &o2NewEntry)
        p2NewEntry.o2NextEntry = self.getP2IS().o2FirstEntry
        self.getP2IS().o2FirstEntry = o2NewEntry
        if self.getP2IS().o2LastEntry == 0:
            self.getP2IS().o2LastEntry = self.getP2IS().o2FirstEntry

    cpdef append(PList self, object value):
        cdef:
            Offset o2NewEntry
            CListEntry   *p2NewEntry = self.newEntry(value, &o2NewEntry)
        p2NewEntry.o2NextEntry = 0
        if self.getP2IS().o2LastEntry == 0:
            self.getP2IS().o2FirstEntry = o2NewEntry
        else:
            # Caveat!
            # http://stackoverflow.com/questions/11498441/what-is-this-kind-of-assignment-in-python-called-a-b-true
            p2LastEntry =  (
                <CListEntry *>self.trx.offset2Address(self.getP2IS().o2LastEntry))
            p2LastEntry.o2NextEntry = o2NewEntry
        self.getP2IS().o2LastEntry = o2NewEntry

    def __iter__(self):
        cdef:
            Offset o2Entry = self.getP2IS().o2FirstEntry
            CListEntry   *p2Entry
            PersistentMeta valueClass = (<ListMeta>(self.ptype)).valueClass
        while o2Entry:
            p2Entry = <CListEntry *>(self.trx.offset2Address(o2Entry))
            # LOG.info(p2Entry.o2 Value)
            yield valueClass.resolveAndCreateProxyFA(self.trx, p2Entry + 1)
            o2Entry = p2Entry.o2NextEntry

cdef class List(TypeDescriptor):
    meta = ListMeta
    proxyClass = PList
    minNumberOfParameters=1
    maxNumberOfParameters=1


# ================ Structure ================

# Inheritance among persistent structures
# ---------------------------------------
# The offset stored in a PField object is valid only in the persistent
# structure (i.e. StructureMeta instance) the PField object was added to. When
# a new persistent structure inherits from an existing one, the persistent
# fields of the latter need to be re-added to the former and their offsets
# re-computed.

# Fields are "virtual": a reference to a field called "foo" in code in any of
# base classes and even in the derived class always refers to the same field.

# The code in each base class and in the derived class may rely on the "foo"
# field having a particular structure. The assumptions of the
# individual classes about the structure of "foo" may be conflicting,
# which we need to detect and prevent creating the derived class.
# Although Python typically cares about the structure and not the type of an
# object, for now we define "conflicting" in a nominal sense
# (see http://en.wikipedia.org/wiki/Nominal_type_system). The rationale is that
# the implementation of conflict-detection seems to be easier with this choice.
# A structural conflict definition may be less restrictive, so at a later stage
# the current conflict detection may be replaced with one based on that.
# For now here is the nominal conflict definition:

# Field #1 and field #2 (defined in a different persistent structure) are
# conflicting if
#  - they both use the same name and
#  - both fields are persistent structures and
#  - the type of field #1 is not a sub-type of field #2 and
#  - the type of field #2 is not a sub-type of field #1 and
# With this definition the type of the field in the derived class will be the
# more derived of the types of the two fields.

def _getAllMembers(c):
    for base in reversed(c.__bases__):
        for item in _getAllMembers(base):
            yield item
    for k, v in vars(c).items():
        yield (c, k, v)


cdef _addInheritedFields(StructureMeta ptype, bases, dict newFields):
    """ Update the 'newFields' argument with the fields defined in the bases.

        @param bases: tuple of base classes

        @param newFields: A dictionary containing the names and types of the
                        fields declared in the body of the class statement
                        defining the persistent structure. Will be updated with
                        the fields defined in the base classes.
        @raise TypeError: Raised when an inherited field is overridden with a
                        conflicting type or the bases classes contain fields
                        with conflicting types.
    """
    cdef:
        StructureMeta baseStructureMeta
        PersistentMeta inheritedFieldType
    # We rely on the bases already having copied their inherited fields
    # (no need for recursion)
    for base in bases:
        if isinstance(base, StructureMeta):
            baseStructureMeta = <StructureMeta>base
            if baseStructureMeta.storage is not ptype.storage:
                raise TypeError("Cannot derive a persistent structure in "
                                "storage {0} from a persistent type defined "
                                "in storage {1}."
                                .format(ptype.storage.fileName,
                                        baseStructureMeta.storage.fileName)
                                )
            for fieldName in baseStructureMeta.pfields:
                inheritedFieldType = <PersistentMeta?>\
                    (baseStructureMeta.pfields[fieldName]).ptype
                _addInheritedField(ptype, base, fieldName,
                                   inheritedFieldType, newFields)
        else:
            try:
                pickle.dumps(base)
            except (TypeError, pickle.PicklingError):
                raise TypeError("Cannot use the non-pickleable volatile class "
                                "{0} as a base class in the definition of "
                                "the persistent structure {1}"
                                .format(base, ptype))
            for owner, fieldName, fieldValue in _getAllMembers(base):
                if isinstance(fieldValue, PersistentMeta):
                    warn("Attempt to re-use persistent field '{0}' defined in "
                         "volatile class {1} in the definition of persistent "
                         "class {2} is ignored."
                         .format(fieldName, owner, ptype),
                         RuntimeWarning)

cdef _addInheritedField(StructureMeta ptype, base, str fieldName,
                        PersistentMeta inheritedFieldType, dict newFields):
    cdef PersistentMeta newFieldType
    try:
        newFields[fieldName]
    except KeyError:
        # 1st encounter with this fieldName
        newFields[fieldName] = inheritedFieldType
    else:
        if not isinstance(newFields[fieldName], PersistentMeta):
            raise TypeError("'{0}' must be a persistent field, not {1}"
                            .format(fieldName, newFields[fieldName]))
        newFieldType = <PersistentMeta>(newFields[fieldName])
        # field {fieldName} already exists, types must not conflict
        if issubclass(inheritedFieldType, newFieldType):
            # The inherited field is subclass of the new field,
            # so we let the inherited rule
            newFields[fieldName] = inheritedFieldType
        elif not issubclass(newFieldType, inheritedFieldType):
            # re-definition with a conflicting type
            raise TypeError("Cannot re-define field '{1}' defined "
                            "in {0!r} as {3!r} to be of type {2!r}!"
                            .format(base, fieldName,
                                    newFieldType,
                                    inheritedFieldType))

threadLocal = threading.local()
cdef class StructureMeta(PersistentMeta):

    def __init__(ptype, className, bases, dict attribute_dict):
        # assert bases==(Structure,), bases  # no base classes supported yet
        cdef Storage storage = getattr(threadLocal, 'currentStorage', None)
        if storage is None:
            raise Exception("Types with {ptype.__class__.__name__} as "
                            "__metaclass__ must be defined in the "
                            "populateSchema() method of Storage subclasses!"
                            .format(ptype=ptype)
                            )
        PersistentMeta.__init__(ptype, storage, className, PStructure, 0)
        ptype.fields = list()
        ptype.pfields = dict()
        _addInheritedFields(ptype, bases, attribute_dict)
        for fieldName, fieldType in sorted(attribute_dict.items()):
            if isinstance(fieldType, PersistentMeta):
                ptype.addField(fieldName, fieldType)
            else:
                try:
                    pickle.dumps(fieldType)
                except (TypeError, pickle.PicklingError):
                    raise TypeError("'{0}' is defined as a non-pickleable "
                                    "volatile member {1} in a persistent "
                                    "structure".format(fieldName, fieldType))
        ptype.NamedTupleClass = namedtuple(className, ptype.pfields.keys())
        LOG.debug('Created {ptype} from meta-class {meta} using proxy '
                  '{proxyClass} allocationSize {allocationSize}'
                  .format(ptype=ptype, meta=type(ptype), proxyClass=PStructure,
                          allocationSize=ptype.allocationSize)
                  )

    cdef addField(StructureMeta ptype, name, PersistentMeta fieldType):
        ptype.fields.append((name, fieldType.__name__))
        cdef PField pfield = PField(ptype.allocationSize, name, fieldType)
        ptype.pfields[name] = pfield
        setattr(ptype, name, pfield)
        ptype.allocationSize += fieldType.assignmentSize
        LOG.debug(
            'Added {field} to {ptype}' .format(field=pfield, ptype=ptype))

    def reduce(ptype):
        d = dict(ptype.__dict__)
        for name in ['__metaclass__', '__dict__', '__weakref__', '__module__',
                     'storage', ]:
            d.pop(name, None)
        # force the list, as we can't modify the dict while iterating over it
        for k, v in list(d.items()):
            if isinstance(v, PField):
                del d[k]
        bases = list()
        for base in ptype.__bases__:
            if type(base) is StructureMeta:
                base = ('persistentBase', base.__name__)
            else:
                base = ('volatileBase', base)
            bases.append(base)
        return ('StructureMeta', ptype.__name__,  # name of the class
                bases,         # base classes
                d,             # volatile members (docstring, etc.)
                ptype.fields   # persistent fields
                )


# The below two functions are copied from
# https://bitbucket.org/hpk42/execnet/src/tip/execnet/gateway.py?at=default
# (Published under the MIT license)
def _find_non_builtin_globals(source, codeobj):
    try:
        import ast
    except ImportError:
        return None
    try:
        import __builtin__
    except ImportError:
        import builtins as __builtin__

    vars = dict.fromkeys(codeobj.co_varnames)
    return [
        node.id for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Name) and
        node.id not in vars and
        node.id not in __builtin__.__dict__
    ]


def _source_of_function(function):
    if function.__name__ == '<lambda>':
        raise ValueError("can't evaluate lambda functions'")
    # XXX: we dont check before remote instanciation
    #      if arguments are used propperly
    args, varargs, keywords, defaults = inspect.getargspec(function)
    if args[0] != 'channel':
        raise ValueError('expected first function argument to be `channel`')

    if PY_MAJOR_VERSION == 3:
        closure = function.__closure__
        codeobj = function.__code__
    else:
        closure = function.func_closure
        codeobj = function.func_code

    if closure is not None:
        raise ValueError("functions with closures can't be passed")

    try:
        source = inspect.getsource(function)
    except IOError:
        raise ValueError("can't find source file for %s" % function)

    source = textwrap.dedent(source)  # just for inner functions

    used_globals = _find_non_builtin_globals(source, codeobj)
    if used_globals:
        raise ValueError(
            "the use of non-builtin globals isn't supported",
            used_globals,
        )

    return source

cdef class PStructure(AssignedByReference):
    """ A structure is like a mutable named tuple.

        Structures are usable as hash keys (they are hashable), but prepare
        for surprises if you do so and change the contents of the structure
        after initialisation.

        Structures lack the 'greater than / less than' relational operators,
        so they are not usable as keys in skip lists.

        Structures can be compared for (non-)equality. They are
        compared field-by-field, accessing via ``getattr()``.
        Extra fields on the compared-to-object are ignored.

        Accessing the ``contents`` attribute of a structure instance will
        return a named tuple. Assigning to the attribute will set the
        contents of the structure to the assigned value,
        which must have at least the attributes the structure has fields.
    """
    def __init__(PStructure self, value=None, **kwargs):
        cdef PField pfield
        for pfield in (<StructureMeta>self.ptype).pfields.values():
            pfield.ptype.clear(self.offset + pfield.offset)
        if value is not None:
            self.set(value)
        for k, v in kwargs.items():
            setattr(self, k, v)

    # The offset is not OK here: it must match the hash of the volatile object!
    def __hash__(self, ):
        return hash(self.get())

    cdef int richcmp(PStructure self, other, int op) except? -123:
        cdef:
            Persistent value
            PField pfield
            bint doesDiffer
        if other is None:
            doesDiffer = True
        else:
            doesDiffer = False
            for pfield in (<StructureMeta>self.ptype).pfields.values():
                value = pfield.get(self)
                try:
                    otherValue = getattr(other, pfield.name)
                except AttributeError:
                    doesDiffer = True
                    break
                else:
                    if value is None:
                        if otherValue is not None:
                            doesDiffer = True
                            break
                    else:
                        if value.richcmp(otherValue, 3):
                            doesDiffer = True
                            break
        if op==2:
            return not doesDiffer
        if op==3:
            return doesDiffer
        raise TypeError('{0} does not define a sort order!'.format(self.ptype))

    cdef get(PStructure self):
        cdef:
            PField  pfield
            dict    pfields = (<StructureMeta>self.ptype).pfields
            list    values = list()
            type    NamedTupleClass = (<StructureMeta>
                                       self.ptype).NamedTupleClass
        for fieldName in NamedTupleClass._fields:
            pfield = pfields[fieldName]
            values.append(pfield.get(self))
        return NamedTupleClass(*values)

    cdef set(PStructure self, value):
        cdef:
            PField  pfield
            dict    pfields = (<StructureMeta>self.ptype).pfields
        for pfield in pfields.values():
            pfield.set(self, getattr(value, pfield.name))

    property contents:
        def __get__(PStructure self):
            return self.get()

        def __set__(PStructure self, value):
            self.set(value)

cdef class PField(object):

    def __init__(PField self, int offset, str name, PersistentMeta ptype=None):
        self.offset = offset  # offset into the structure
        self.ptype = ptype
        self.name = name

    def __repr__(self):
        return ('PField({1}, offset={0}, ptype={2})'
                .format(self.offset, self.name, self.ptype))

    property size:
        def __get__(PField self):
            return self.ptype.assignmentSize

    def __get__(PField self, PStructure owner, ownerClass):
        if owner is None:
            return self
        else:
            return self.get(owner)

    cdef Persistent get(PField self, PStructure owner):
        assert owner is not None
        owner.ptype.assertSameStorage(self.ptype)
#         LOG.debug( bytes(('getting', hex(owner.offset), self.offset)) )
        return self.ptype.resolveAndCreateProxy(owner.trx, 
                                                owner.offset + self.offset)

    def __set__(PField self, PStructure owner, value):
        self.set(owner, value)

    cdef set(PField self, PStructure owner, value):
        assert owner is not None
#         LOG.debug( str(('setting', hex(owner.offset), self.offset, value)) )
        self.ptype.assign(owner.trx, owner.p2InternalStructure + self.offset, 
                          value)

# ================ Storage ================


cdef class Storage(object):

    def __init__(self, fileName, unsigned long fileSize=0,
                 unsigned long stringRegistrySize=0
                 ):
        self.backingFile = BackingFile(fileName, fileSize)
        self.stringRegistrySize = stringRegistrySize
        self.schema = ModuleType('schema')
        self.typeList = list()

        self.define(Int)
        self.define(Float)
        self.define(__ByteString('ByteString'))
        self.define(List('ListOfByteStrings')[self.schema.ByteString])
        self.define(Set('SetOfByteStrings')[self.schema.ByteString])
        self.trx = None
        self.setTrx(Trx(self.backingFile))

    cpdef Trx setTrx(self, Trx trx):
        cdef:
            PersistentMeta Root
            Trx oldTrx = self.trx

        if trx is None:
            self.trx = None
            self._stringRegistry = None
            self._root = None
            return oldTrx
        trx.assertNotClosed()
        self.trx = trx
        self.p2StorageHeader = \
                <CStorageHeader*>self.trx.payloadRegion.baseAddress

        if self.p2StorageHeader.freeOffset == 0:
            self.p2StorageHeader.freeOffset = self.trx.payloadRegion.o2Base

        if self.p2StorageHeader.o2ByteStringRegistry:
            LOG.debug("Using the existing stringRegistry")
            self._stringRegistry = \
                ((<PersistentMeta?>self.schema.SetOfByteStrings)
                    .createProxy(self.trx, 
                                 self.p2StorageHeader.o2ByteStringRegistry))
        else:
            LOG.debug("Creating a new stringRegistry")
            self._stringRegistry = \
                    self.schema.SetOfByteStrings(self.stringRegistrySize)
            self.p2StorageHeader.o2ByteStringRegistry = \
                    self._stringRegistry.offset
        LOG.debug('self.p2StorageHeader.o2ByteStringRegistry: {0}'.format(
            hex(self.p2StorageHeader.o2ByteStringRegistry)))

        if self.p2StorageHeader.o2PickledTypeList:
            self.loadSchema()
        else:
            self.createSchema()
        try:
            Root = self.schema.Root
        except AttributeError:
            raise Exception(
                "The schema contains no type called 'Root'.")
        LOG.debug('self.p2StorageHeader.o2Root #1: {0}'.format(
            hex(self.p2StorageHeader.o2Root)))
        if self.p2StorageHeader.o2Root:
            self._root = Root.createProxy(self.trx, 
                                           self.p2StorageHeader.o2Root)
        else:
            self._root = Root()
            self.p2StorageHeader.o2Root = self._root.offset
        LOG.debug('self.p2StorageHeader.o2Root #2: {0}'.format(
            hex(self.p2StorageHeader.o2Root)))
        return oldTrx

    def createSchema(self):
        LOG.debug("Creating a new schema")
        cdef PList pickledTypeList = <PList?>self.schema.ListOfByteStrings()

        self.p2StorageHeader.o2PickledTypeList = pickledTypeList.offset
        try:
            threadLocal.currentStorage = self
            StructureMeta('Structure', (PStructure,), dict())
            self.populateSchema()
        finally:
            threadLocal.currentStorage = None

        for ptype in self.typeList:
            if ptype.__name__ not in ('ByteString', 'Int', 'Float', 
                                      'SetOfByteStrings', 'ListOfByteStrings'):
                x = ptype.reduce()
#                             LOG.debug( 'pickle data:'+ repr(x))
                s = self._stringRegistry.get(pickle.dumps(x))
                pickledTypeList.append(s)
                del s  # do not leave a dangling proxy around
        LOG.debug("Saved the new schema.")

    def loadSchema(self):
        LOG.debug("Loading the previously saved schema")

        cdef PList pickledTypeList = \
            <PList>((<PersistentMeta?>self.schema.ListOfByteStrings)
                        .createProxy(self.trx, 
                                     self.p2StorageHeader.o2PickledTypeList))

        for s in pickledTypeList:
            t = pickle.loads(s.contents)
            if t[0] == '_typedef':
                className, meta, proxyClass = t[1:4]
                typeParams = [
                    getattr(self.schema, typeParam[1])
                    if (isinstance(typeParam, tuple) and
                        typeParam[0] == 'PersistentMeta')
                    else typeParam
                    for typeParam in t[4:]
                ]
                ptype = meta._typedef(self, className, proxyClass, *typeParams)
            elif t[0] == 'StructureMeta':
                className, bases, attributeDict = t[1:4]
                base2  = list()
                for base in bases:
                    baseKind, baseX = base
                    if baseKind == 'persistentBase':
                        base = getattr(self.schema, baseX)
                    else:
                        assert baseKind == 'volatileBase', baseKind
                        base = baseX
                    base2.append(base)
                for fieldName, fieldTypeName in t[4]:
                    attributeDict[fieldName] = getattr(
                        self.schema, fieldTypeName)
                try:
                    threadLocal.currentStorage = self
                    ptype = StructureMeta(className, tuple(base2), attributeDict)
                finally:
                    threadLocal.currentStorage = None
            else:
                assert False
            self.typeList.append(ptype)

    cdef Offset allocate(self, int size) except 0:
        self.trx.assertNotClosed()
        cdef:
            Offset origFreeOffset = self.p2StorageHeader.freeOffset
            Offset newFreeOffset = self.p2StorageHeader.freeOffset + size
        if newFreeOffset > self.backingFile.realFileSize:
            raise DbFullException("{self.fileName} is full.".format(self=self))
        self.p2StorageHeader.freeOffset = newFreeOffset
#         LOG.debug( "allocated: {origFreeOffset}, {size},
#               {newFreeOffset}".format(**locals()))
        return origFreeOffset

    property stringRegistry:
        def __get__(self):
            assert self.trx
            self.trx.assertNotClosed()
            return self._root

    property root:
        def __get__(self):
            assert self.trx
            self.trx.assertNotClosed()
            return self._stringRegistry

    def commit(self):
        self.setTrx(Trx(self.backingFile))
        self.trx.close(Persistent, doCommit=True)

    def rollback(self):
        self.setTrx(Trx(self.backingFile))
        self.trx.close(Persistent, doCommit=False)

    cpdef close(self):
        """ Flush and close the storage.

            Triggers a garbage collection to break any unreachable cycles
            referencing the storage.
        """
        self.trx.close(Persistent, doCommit=False)
        BackingFile.close(self)

    cdef registerType(self, PersistentMeta ptype):
        if hasattr(self.schema, ptype.__name__):
            raise Exception(
                "Redefinition of type '{ptype.__name__}'.".format(ptype=ptype))
        setattr(self.schema, ptype.__name__, ptype)
        self.typeList.append(ptype)

    def defineType(Storage storage, TypeDescriptor typeDescriptor):
        cdef:
            type meta = typeDescriptor.meta
        # need to check if they are filled in
        typeDescriptor.verifyTypeParameters(typeDescriptor.typeParameters)
        return meta._typedef(storage, typeDescriptor.className,
                             typeDescriptor.proxyClass,
                             *typeDescriptor.typeParameters)

    def define(Storage storage, object o):
        if isinstance(o, TypeDescriptor):
            return storage.defineType(o)
        elif isinstance(o, type) and issubclass(o, TypeDescriptor):
            return storage.defineType(o())
        elif isinstance(o, ModuleType):
            return o.defineTypes(storage)
        else:
            raise TypeError("Don't know how to define {o}".format(o=repr(o)))

    cpdef object internValue(Storage self, str typ, value):
        if typ == 'time':
            return mktime(strptime(value, '%Y-%m-%d %H:%M:%S %Z'))
        elif typ == 'string':
            return self._stringRegistry.find(value)
        elif typ is None:
            return value
        else:
            raise TypeError(str(typ))

    def populateSchema(self):
        pass

