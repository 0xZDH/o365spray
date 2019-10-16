#!/usr/bin/env python3

import asyncio

class TaskPool(object):
    """ This class manages the pool of tasks being run keeping it to a fixed size """
    # https://medium.com/@cgarciae/making-an-infinite-number-of-requests-with-python-aiohttp-pypeln-3a552b97dc95
    # https://github.com/cgarciae/pypeln/blob/master/pypeln/asyncio_task.py#L638

    # _tasks: Set() to store unique tasks to run
    # _semaphore: Limit number of tasks to be run at any single time
    def __init__(self, workers):
        self._tasks     = set()
        self._semaphore = asyncio.Semaphore(workers)

    # Acquire 1 from _semaphore and add task to list for execution
    # -> aquiring decrements the counter by 1 and if 0, wait until a spot opens
    # Once task concludes, run _on_task_done
    async def put(self, coro):
        await self._semaphore.acquire()
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._on_task_done)

    # Remove completed task from _tasks list
    # Release 1 from _semaphore to allow another task to be run
    # -> release increments the counter by 1
    def _on_task_done(self, task):
        self._tasks.remove(task)
        self._semaphore.release()

    # Run tasks using gather()
    async def join(self):
        await asyncio.gather(*self._tasks)

    # Asyncio function: https://www.python.org/dev/peps/pep-0492/
    async def __aenter__(self):
        return self

    # Asyncio function: https://www.python.org/dev/peps/pep-0492/
    def __aexit__(self, exc_type, exc, tb):
        return self.join()