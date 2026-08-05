const { withDangerousMod } = require('@expo/config-plugins');
const fs = require('fs');
const path = require('path');

const withTestSpecs = (config) => {
  return withDangerousMod(config, [
    'ios',
    async (config) => {
      const podfilePath = path.join(config.modRequest.platformProjectRoot, 'Podfile');
      let podfileContent = fs.readFileSync(podfilePath, 'utf8');

      const customPodLine = "pod 'ReactNativeSilicon', :path => '../../ios', :testspecs => ['Tests']";

      if (!podfileContent.includes(":testspecs => ['Tests']")) {
        podfileContent = podfileContent.replace(
          'use_expo_modules!',
          `${customPodLine}\n  use_expo_modules!`
        );
        fs.writeFileSync(podfilePath, podfileContent);
      }

      return config;
    },
  ]);
};

module.exports = ({ config }) => {
  return withTestSpecs({
    ...config,
    name: "react-native-silicon-example",
    slug: "react-native-silicon-example",
    version: "1.0.0",
    orientation: "portrait",
    icon: "./assets/icon.png",
    //userInterfaceStyle: "light",
    newArchEnabled: true,
    splash: {
        image: "./assets/splash-icon.png",
        resizeMode: "contain",
        backgroundColor: "#ffffff"  
    },
    ios: {
        supportsTablet: true,
        bundleIdentifier: "co.alephnull.reactnative.silicon.example",
        infoPlist: {
            NSFaceIDUsageDescription: "Allow $(PRODUCT_NAME) to use Face ID to securely generate and access cryptographic keys."
        }
    },
    android: {
        adaptiveIcon: {
            foregroundImage: "./assets/adaptive-icon.png",
            backgroundColor: "#ffffff"
        },
        edgeToEdgeEnabled: true,
        predictiveBackGestureEnabled: false,
        package: "co.alephnull.reactnative.silicon.example"
    },
    web: {
        favicon: "./assets/favicon.png"
    }
  });
};