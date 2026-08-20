// Learn more https://docs.expo.io/guides/customizing-metro
const { getDefaultConfig } = require('expo/metro-config');
const path = require('path');

const projectRoot = __dirname;
const workspaceRoot = path.resolve(projectRoot, '..');

const config = getDefaultConfig(projectRoot);

config.resolver.blockList = [
  ...Array.from(config.resolver.blockList ?? []),
  // npm v7+ will install ../node_modules/react and ../node_modules/react-native because of peerDependencies.
  // To prevent the incompatible react-native between ./node_modules/react-native and ../node_modules/react-native,
  // excludes the one from the parent folder when bundling.
  //new RegExp(path.resolve('..', 'node_modules', 'react')),
  //new RegExp(path.resolve('..', 'node_modules', 'react-native')),

  // Ignore tests when bundling
  /.*__tests__.*/,
  /.*__mocks__.*/,
  /.*__test_utils__.*/,
];

config.resolver.nodeModulesPaths = [
  path.resolve(projectRoot, 'node_modules'),
  path.resolve(workspaceRoot, 'node_modules'),
];

config.resolver.extraNodeModules = {
  'react-native-silicon': '..',
};

config.watchFolders = [workspaceRoot];

config.transformer.getTransformOptions = async () => ({
  transform: {
    experimentalImportSupport: false,
    inlineRequires: true,
  },
});

//config.resolver.disableHierarchicalLookup = false;

module.exports = config;
