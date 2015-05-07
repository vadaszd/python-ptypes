'''
Created on 2015.05.05.

@author: dini
'''
import unittest
import random
from functools import partial
from collections import defaultdict

from mvcc import PagePool, Page, PageVersion, Transaction

class MyPage(Page):
 
    def update(self, key, view, trx, ):
        new, old = trx.updatePage(self)
        new.data = old.data.copy()
        new.data[key] += 1
        view[self.ordinal] = new.data

    def read(self, key, view, trx, ):
        view[self.ordinal] = trx.readPage(self).data

class MyPageVersion(PageVersion):

    def __init__(self, writerTrx, page, prevPageVersion):
        PageVersion.__init__(self, writerTrx, page, prevPageVersion)
        self.data = defaultdict(int)  # integer values keyed by frozensets


class Action(object):

    def createPlan(self, pagePool, op, view):
        pages = random.sample(pagePool, random.randint(0, self.maxNumPagesInTrx))
        key = frozenset(page.ordinal for page in pages)
        operations = list(partial(op, page, key, view) 
                          for page in pages)
        return operations, key

    def __init__(self, pagePool, maxNumPagesInTrx):
        self.maxNumPagesInTrx = maxNumPagesInTrx
        self.view = dict()  # {ordinal: data}
        updates, self.updatedKey = \
            self.createPlan(pagePool, MyPage.update, self.view)
        reads, self.readKey = \
            self.createPlan(pagePool, MyPage.read, self.view)
        self.operations = updates + reads
        random.shuffle(self.operations)

    def assertSameResults(self, key):
        datas = [self.view[ordinal] for ordinal in key]
        try:
            value1 = datas[0][key]
        except IndexError: pass
#             print self.trx.trxNumber, key
        else:
#             print self.trx.trxNumber, key, [data[key] for data in datas]
            assert all(value1 == data[key] for data in datas), \
                    [key, datas]

    def run(self):
        trx = Transaction()
        for operation in self.operations:
            operation(trx=trx)
            page, key, view = operation.args
#             print (self.trx.trxNumber, operation.func.__name__, 
#                    page.ordinal, key)
            yield 
        self.assertSameResults(self.readKey)
        self.assertSameResults(self.updatedKey)
        trx.end()

class Test(unittest.TestCase):

    def testMvcc(self):
        return
        pp = PagePool((((), {}) for _ in range(5)), Page, PageVersion)
        p0 = pp[0]
        t1 = Transaction()
        t2 = Transaction()
        print t1.readPage(p0)
        print t2.readPage(p0)
        print t1.updatePage(p0)
        print t2.updatePage(p0)
        t3 = Transaction()
        print t3.readPage(pp[1])
        print t1.end(), "t1"
        print t3.updatePage(p0)
        t4 = Transaction()
        t5 = Transaction()
        print t4.updatePage(pp[1])
        print t2.end(), "t2"
        print t4.end(), "t4"
        print t5.updatePage(pp[1])
        print t5.end(), "t5"
        print t3.end(), "t3"

    def testMvccRandomly(self):
        pagePool = PagePool((((), {}) for _ in range(500)), MyPage, 
                            MyPageVersion)
        random.seed(13)
        generators = set()
        for _ in range(300):
            generators.add(Action(pagePool, 3).run())
        while generators:
            generator = random.choice(list(generators))
            try:
                generator.next()
            except StopIteration:
                generators.remove(generator)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testMvcc']
    unittest.main()