# Contributing Guidelines

Thank you for your interest in contributing to the SmartThings Device SDK(STDK for short) project. Please read through this document before submitting any issues or pull requests.

## Contributing

If you encounter any bugs, have suggestions for new features, please contribute to our project. It is really appreciated. If you need to have additional information about contribution or have a question, please send an [e-mail](stdk@samsung.com). We will respond to your mail promptly.

### Contributor License Agreement

A Contributor is a developer who wishes to contribute to the Project at any level.  If you would like to become a contributor to this project, please fill out & sign the [Contributor License Agreement (CLA)](https://github.com/SmartThingsCommunity/st-device-sdk-c/blob/master/doc/SAMSUNGCLA.docx) and return it.

Specially, we may ask you to sign it for larger changes. In this case, once we receive it, we'll be able to accept your pull requests according to relevant laws.

### Reporting Bugs/Feature Request

We welcome you to use the GitHub issue tracker to report bugs or suggest features. Please try to include as much information as you can.  This is very helpful for us to respond effectively to your bug report or contribution.

> Note :
>
> When using the GitHub issue tracker, please don't upload your privacy data(e.g. Serial Number, MNID and so on) in there. Please just include the examples below.

Examples of useful information :

- A reproducible test steps
- The STDK version being used
- The Device(Board Name) & BSP information being used (e.g. WEMOS D1 Mini & esp8266)
- If there is, any modifications you've made
- If there is, anything unusual about your environment

### Pull Requests

We would love to accept your patches. Please contribute patches via Pull Requests.

According to the our SCM(Software Configuration Management) policy, the `master` branch will be managed for official releases. Therefore we will just merge your patches into the `develop` branch after minimally testing to ensure nothing major is broken. And these patches which were merged into the `develop` branch through several Pull Requests will eventually be integrated into the `master` branch after passing the test on all supported platforms.

1. Fork the repository.
2. Develop based on the [develop](https://github.com/SmartThingsCommunity/st-device-sdk-c/tree/develop) branch.
3. Ensure that your code adheres to the existing style in the sample to which you are contributing.
4. Ensure local tests pass about your code changes.
5. In order to ensure that the Pull Request is integrated without a merge conflict, please create a Pull Request based on the latest `develop` branch.
6. Finally, create a pull request against the `develop` branch.

### Security issue notifications

If you discover a potential security issue in this project we ask that you notify us via our [e-mail](mailto:stdk@samsung.com). Please do NOT create a public GitHub issue.

### License

Your contribution will be licensed under the [Apache License Ver2.0](https://github.com/SmartThingsCommunity/st-device-sdk-c/blob/master/LICENSE). If another license code is found in your patches, we will ask you to modify them. If possible, please ensure that there are no another licenses in your contribution prior to creation a Pull Request.