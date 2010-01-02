import os
import unittest
import yaml

def run_suites(suite_names):
  """Run the given list of test suite names corresponding to the SUITES
  configuration global.
  """
  suites = yaml.load(
      open(
        os.path.join(
          os.path.dirname(os.path.abspath(__file__)), 'config.yaml')))

  def build_names(agg, name):
    modules = suites[name]
    for module in modules:
      classes = module['classes']
      for c in classes:
        tests = c['tests']
        for t in tests:
          n = module['module'], c['name'], t
          if n not in agg:
            agg.append(n)
    return agg

  def build_test(loc):
    module_name, class_name, test_name = loc
    module = __import__('tests.'+ module_name, fromlist='tests')
    return getattr(module, class_name)(test_name)

  unittest.TextTestRunner().run(unittest.TestSuite(
    map(build_test, reduce(build_names, suite_names, []))))
