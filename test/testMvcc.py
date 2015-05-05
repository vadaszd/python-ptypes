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
 
    def update(self, trx, key, results):
        new, old = trx.updatePage(self)
        new.data = old.data.copy()
        new.data[key] += 1
        results.append(new.data[key])

    def read(self, trx, key, results):
        results.append(trx.readPage(self).data[key])

class MyPageVersion(PageVersion):

    def __init__(self, writerTrx, page, prevPageVersion):
        PageVersion.__init__(self, writerTrx, page, prevPageVersion)
        self.data = defaultdict(int)  # integer values keyed by frozensets


class Action(object):

    def createPlan(self, pagePool, trx, op):
        results = list()
        pages = frozenset(random.sample(pagePool, random.randint(0,5)))
        operations = list(partial(op, page, trx, pages, results) for page in pages)
        return operations, results, pages

    def __init__(self, pagePool):
        trx = Transaction()
        updates, self.updateResults, self.updatePages = \
            self.createPlan(pagePool, trx, MyPage.update)
        reads, self.readResults, self.readPages = \
            self.createPlan(pagePool, trx, MyPage.read)
        self.operations = updates + reads
        random.shuffle(self.operations)

    def assertSameResults(self, pages, results):
        if results:
            result1 = results[0]
            assert all(result == result1 for result in results), [pages, results]

    def run(self):
        for operation in self.operations:
            operation()
            yield 
        self.assertSameResults(self.readPages, self.readResults)
        self.assertSameResults(self.updatePages, self.updateResults)

class Test(unittest.TestCase):

    def testMvcc(self):
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
        pagePool = PagePool((((), {}) for _ in range(5)), MyPage, 
                            MyPageVersion)
        random.seed(13)
        generators = set()
        for _ in range(120):
            generators.add(Action(pagePool).run())
        while generators:
            generator = random.choice(list(generators))
            try:
                generator.next()
            except StopIteration:
                generators.remove(generator)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testMvcc']
    unittest.main()