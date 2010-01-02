import unittest
import yaml

SUITES = {
    'full': [
            ('basic','RobotsTxt',['test_robotsTxt']),
            ('basic','NotFound',['test_notFound']
        )]
    }

def run_suites(suite_names):
  """Run the given list of test suite names corresponding to the SUITES
  configuration global.
  """
  def build_names(agg, name):
    parts = SUITES[name]
    for part in parts:
      tests = part[2]
      for test in tests:
        n = part[0], part[1], test
        if not n in agg:
          agg.append(n)
    return agg

  def build_test(loc):
    module_name, class_name, test_name = loc
    module = __import__('tests.'+ module_name, fromlist='tests')
    return getattr(module, class_name)(test_name)

  unittest.TextTestRunner().run(unittest.TestSuite(
    map(build_test, reduce(build_names, suite_names, []))))
