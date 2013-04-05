import logging

"""
Enhance the built in logging a little bit.

Add a TRACE level (which is more verbose than DEBUG).
"""

TRACE_LEVEL = 5

logging.addLevelName(TRACE_LEVEL, "TRACE")
def trace(self, message, *args, **kwargs):
	if self.isEnabledFor(TRACE_LEVEL):
		self._log(TRACE_LEVEL, message, args, **kwargs)
logging.Logger.trace = trace
def trace_module(message, *args, **kwargs):
	trace(logging.getLogger(), message, *args, **kwargs)
logging.trace = trace_module
