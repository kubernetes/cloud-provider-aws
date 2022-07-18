## v1.22.3
* [Cherry Pick from master to 1.22] [FIXES] [Tagging Controller] Fix issues in tagging controller ([#389](https://github.com/kubernetes/cloud-provider-aws/pull/389), @saurav-agarwalla)

## v1.21.2
* [Cherry Pick from master to 1.21] [FIXES] [Tagging Controller] Fix issues in tagging controller ([#390](https://github.com/kubernetes/cloud-provider-aws/pull/390), @saurav-agarwalla)

## v1.20.2
* Automated cherry pick of #223: Add ENI support for nodes(for Fargate nodes)
#387: Fix issues in tagging controller ([#392](https://github.com/kubernetes/cloud-provider-aws/pull/392), @saurav-agarwalla)

## v1.21.1
* Automated cherry pick of #376: Stop tagging latest for release branches ([#382](https://github.com/kubernetes/cloud-provider-aws/pull/382), @hakman)
* Update cloud build config for v1.21 ([#374](https://github.com/kubernetes/cloud-provider-aws/pull/374), @hakman)
* Cherry pick E2E test changes and fix failing tagging controller test for 1.21 ([#369](https://github.com/kubernetes/cloud-provider-aws/pull/369), @saurav-agarwalla)
* Bump dependencies ([#332](https://github.com/kubernetes/cloud-provider-aws/pull/332), @nckturner)

## v1.20.1
* Automated cherry pick of #376: Stop tagging latest for release branches ([#383](https://github.com/kubernetes/cloud-provider-aws/pull/383), @hakman)
* Update cloud build config for v1.20 ([#375](https://github.com/kubernetes/cloud-provider-aws/pull/375), @hakman)
* Cherry pick E2E test changes and fix failing tagging controller test for 1.20 ([#370](https://github.com/kubernetes/cloud-provider-aws/pull/370), @saurav-agarwalla)
* go fmt release-1.20 ([#371](https://github.com/kubernetes/cloud-provider-aws/pull/371), @nckturner)

## v1.20.0
* Automated cherry pick of #308: Add tagging controller configuration
  #334: Stop retrying failed workitem after a certain amount of ([#361](https://github.com/kubernetes/cloud-provider-aws/pull/361), @saurav-agarwalla)
* Release 1.20 ([#183](https://github.com/kubernetes/cloud-provider-aws/pull/183), @ayberk)

## v1.21.0
* Automated cherry pick of #308: Add tagging controller configuration
  #334: Stop retrying failed workitem after a certain amount of ([#358](https://github.com/kubernetes/cloud-provider-aws/pull/358), @saurav-agarwalla)
* Add support for consuming web identity credentials ([#238](https://github.com/kubernetes/cloud-provider-aws/pull/238), @olemarkus)
* Add support for returning IPv6 node addresses ([#230](https://github.com/kubernetes/cloud-provider-aws/pull/230), @hakman)
* Add ENI support for nodes(for Fargate nodes) ([#223](https://github.com/kubernetes/cloud-provider-aws/pull/223), @SaranBalaji90)
* Use kustomize for example manifest ([#221](https://github.com/kubernetes/cloud-provider-aws/pull/221), @nckturner)

## v1.22.1
* Automated cherry pick of #308: Add tagging controller configuration
  #334: Stop retrying failed workitem after a certain amount of ([#357](https://github.com/kubernetes/cloud-provider-aws/pull/357), @saurav-agarwalla)
* Automated cherry pick of #345: Double load balancer timeout from 5 mins to 10 ([#347](https://github.com/kubernetes/cloud-provider-aws/pull/347), @wongma7)

## v1.23.1
* Automated cherry pick of #352: Use short git tag for version and images ([#353](https://github.com/kubernetes/cloud-provider-aws/pull/353), @hakman)
* Automated cherry pick of #345: Double load balancer timeout from 5 mins to 10 ([#346](https://github.com/kubernetes/cloud-provider-aws/pull/346), @wongma7)

## v1.24.0
* Cherry picks ([#356](https://github.com/kubernetes/cloud-provider-aws/pull/356), @nckturner)
* Update Go to v1.18.1 ([#355](https://github.com/kubernetes/cloud-provider-aws/pull/355), @hakman)
* Explain short tag with comment ([#354](https://github.com/kubernetes/cloud-provider-aws/pull/354), @hakman)
* Use short git tag for version and images ([#352](https://github.com/kubernetes/cloud-provider-aws/pull/352), @hakman)
* Trim date prefix from tag in GCB image build ([#350](https://github.com/kubernetes/cloud-provider-aws/pull/350), @rifelpet)
* [Issue #325] Added retry count to abort workitem after a few failed retries ([#334](https://github.com/kubernetes/cloud-provider-aws/pull/334), @nguyenkndinh)
* Bump k8s.io deps to 1.24.0 ([#344](https://github.com/kubernetes/cloud-provider-aws/pull/344), @olemarkus)
* Double load balancer timeout from 5 mins to 10 ([#345](https://github.com/kubernetes/cloud-provider-aws/pull/345), @wongma7)
* Update changelog and readme with v1.23.0 and v1.24.0-alpha.0 ([#337](https://github.com/kubernetes/cloud-provider-aws/pull/337), @nckturner)
* Docs ([#336](https://github.com/kubernetes/cloud-provider-aws/pull/336), @nckturner)

## v1.24.0-alpha.0
* chart: Add extraVolumes and extraVolumeMounts ([#333](https://github.com/kubernetes/cloud-provider-aws/pull/333), @jkroepke)
* Add environment and securityContexts ([#328](https://github.com/kubernetes/cloud-provider-aws/pull/328), @jkroepke)
* Bump dependencies ([#330](https://github.com/kubernetes/cloud-provider-aws/pull/330), @nckturner)
* Issue# 306: Added tagging controller ([#308](https://github.com/kubernetes/cloud-provider-aws/pull/308), @nguyenkndinh)
* Bump k8s version to v1.24.0-alpha.2 ([#320](https://github.com/kubernetes/cloud-provider-aws/pull/320), @nckturner)
* Fix route controller create/delete spam: use instanceIDToNodeName in case node name != private DNS ([#319](https://github.com/kubernetes/cloud-provider-aws/pull/319), @wongma7)
* Fix version ([#317](https://github.com/kubernetes/cloud-provider-aws/pull/317), @nckturner)
* add sts regional endpoint logic ([#313](https://github.com/kubernetes/cloud-provider-aws/pull/313), @prasita123)
* Get e2e tests working in prow ([#312](https://github.com/kubernetes/cloud-provider-aws/pull/312), @nckturner)
* E2E framework ([#304](https://github.com/kubernetes/cloud-provider-aws/pull/304), @nckturner)
* Remove metadata funcs ([#305](https://github.com/kubernetes/cloud-provider-aws/pull/305), @olemarkus)

## v1.23.0
* Bump dependency versions ([#329](https://github.com/kubernetes/cloud-provider-aws/pull/329), @nckturner)
* Fix route controller create/delete spam: use instanceIDToNodeName in case node name != private DNS ([#319](https://github.com/kubernetes/cloud-provider-aws/pull/319), @wongma7)
* Fix version ([#317](https://github.com/kubernetes/cloud-provider-aws/pull/317), @nckturner)
* add sts regional endpoint logic ([#313](https://github.com/kubernetes/cloud-provider-aws/pull/313), @prasita123)
* Get e2e tests working in prow ([#312](https://github.com/kubernetes/cloud-provider-aws/pull/312), @nckturner)
* E2E framework ([#304](https://github.com/kubernetes/cloud-provider-aws/pull/304), @nckturner)
* Remove metadata funcs ([#305](https://github.com/kubernetes/cloud-provider-aws/pull/305), @olemarkus)
* Update charts for v1.23.0-alpha.0 ([#298](https://github.com/kubernetes/cloud-provider-aws/pull/298), @nckturner)

## v1.22.0
* Bump dependencies ([#331](https://github.com/kubernetes/cloud-provider-aws/pull/331), @nckturner)

## v1.23.0-alpha.0
* Tag on create ([#293](https://github.com/kubernetes/cloud-provider-aws/pull/293), @olemarkus)
* Use go-runner as base image ([#295](https://github.com/kubernetes/cloud-provider-aws/pull/295), @wongma7)
* Update aws-sdk-go to v1.42.20 ([#292](https://github.com/kubernetes/cloud-provider-aws/pull/292), @hakman)
* Update k8s dependencies to v1.23.0 ([#291](https://github.com/kubernetes/cloud-provider-aws/pull/291), @hakman)
* Add support for ARM64 builds ([#289](https://github.com/kubernetes/cloud-provider-aws/pull/289), @hakman)
* Update go to v1.17.4 ([#290](https://github.com/kubernetes/cloud-provider-aws/pull/290), @hakman)
* Add support for RBN-based node names ([#286](https://github.com/kubernetes/cloud-provider-aws/pull/286), @olemarkus)
* validate service with mixed protocols ([#287](https://github.com/kubernetes/cloud-provider-aws/pull/287), @nckturner)
* Add a kops example with easy setup script ([#279](https://github.com/kubernetes/cloud-provider-aws/pull/279), @nckturner)
* Add 1.22.0-alpha to README table and helm chart appVersion ([#278](https://github.com/kubernetes/cloud-provider-aws/pull/278), @nckturner)
* Add test for DescribeInstances ([#277](https://github.com/kubernetes/cloud-provider-aws/pull/277), @nckturner)
* [helm] Command line flags can be overridden ([#273](https://github.com/kubernetes/cloud-provider-aws/pull/273), @nckturner)
* Set MaxResults if it is not set ([#274](https://github.com/kubernetes/cloud-provider-aws/pull/274), @nckturner)
* Use promoted images ([#267](https://github.com/kubernetes/cloud-provider-aws/pull/267), @nckturner)

## v1.22.0-alpha.1
* Add support for ARM64 builds ([#289](https://github.com/kubernetes/cloud-provider-aws/pull/289), @hakman)
* Update go to v1.17.4 ([#290](https://github.com/kubernetes/cloud-provider-aws/pull/290), @hakman)
* Add support for RBN-based node names ([#286](https://github.com/kubernetes/cloud-provider-aws/pull/286), @olemarkus)
* validate service with mixed protocols ([#287](https://github.com/kubernetes/cloud-provider-aws/pull/287), @nckturner)
* Add a kops example with easy setup script ([#279](https://github.com/kubernetes/cloud-provider-aws/pull/279), @nckturner)
* Add 1.22.0-alpha to README table and helm chart appVersion ([#278](https://github.com/kubernetes/cloud-provider-aws/pull/278), @nckturner)
* Add test for DescribeInstances ([#277](https://github.com/kubernetes/cloud-provider-aws/pull/277), @nckturner)
* [helm] Command line flags can be overridden ([#273](https://github.com/kubernetes/cloud-provider-aws/pull/273), @nckturner)
* Set MaxResults if it is not set ([#274](https://github.com/kubernetes/cloud-provider-aws/pull/274), @nckturner)
* Use promoted images ([#267](https://github.com/kubernetes/cloud-provider-aws/pull/267), @nckturner)

## v1.22.0-alpha.0
* Add a unit test for sets_ippermissions ([#265](https://github.com/kubernetes/cloud-provider-aws/pull/265), @nckturner)
* Remove inactive and add jaypipes ([#266](https://github.com/kubernetes/cloud-provider-aws/pull/266), @nckturner)
* Fix copy/paste error in IPPermissionSet.Ungroup ([#250](https://github.com/kubernetes/cloud-provider-aws/pull/250), @JoelSpeed)
* Make Node IP families configurable ([#251](https://github.com/kubernetes/cloud-provider-aws/pull/251), @olemarkus)
* run hack/update-netparse-cve.sh ([#261](https://github.com/kubernetes/cloud-provider-aws/pull/261), @aojea)
* Set EC2 instance cache max age to 10 mins ([#259](https://github.com/kubernetes/cloud-provider-aws/pull/259), @kishorj)
* chunk target operatation for aws targetGroup ([#256](https://github.com/kubernetes/cloud-provider-aws/pull/256), @M00nF1sh)
* Remove providerless build option ([#257](https://github.com/kubernetes/cloud-provider-aws/pull/257), @nckturner)
* Add script to facilitate cherry-picking from k/k ([#253](https://github.com/kubernetes/cloud-provider-aws/pull/253), @nckturner)
* Bump k8s dependencies to 1.22 and go to 1.16 ([#248](https://github.com/kubernetes/cloud-provider-aws/pull/248), @rifelpet)
* Add support for consuming web identity credentials ([#238](https://github.com/kubernetes/cloud-provider-aws/pull/238), @olemarkus)
* Add support for returning IPv6 node addresses ([#230](https://github.com/kubernetes/cloud-provider-aws/pull/230), @hakman)
* Add ENI support for nodes(for Fargate nodes) ([#223](https://github.com/kubernetes/cloud-provider-aws/pull/223), @SaranBalaji90)
* Use kustomize for example manifest ([#221](https://github.com/kubernetes/cloud-provider-aws/pull/221), @nckturner)

## v1.21.0-alpha.0
* Add permission for service account token creation ([#214](https://github.com/kubernetes/cloud-provider-aws/pull/214), @nckturner)
* A missing item ([#204](https://github.com/kubernetes/cloud-provider-aws/pull/204), @oguzhanun)
* Cherry-pick: additional subnet configuration for AWS ELB (#97431) ([#210](https://github.com/kubernetes/cloud-provider-aws/pull/210), @nckturner)
* Cherry-pick: delete leaked volume if driver don't know the volume status -- aws (#99664) ([#212](https://github.com/kubernetes/cloud-provider-aws/pull/212), @nckturner)
* Cherry-pick: Use GA topoogy labels for EBS (#99130) ([#211](https://github.com/kubernetes/cloud-provider-aws/pull/211), @nckturner)
* Add Makefile target for windows binary ([#207](https://github.com/kubernetes/cloud-provider-aws/pull/207), @ayberk)
* Bump dependencies to v1.21.0 ([#205](https://github.com/kubernetes/cloud-provider-aws/pull/205), @nckturner)
* Automate helm chart release ([#191](https://github.com/kubernetes/cloud-provider-aws/pull/191), @ayberk)
* Add a docs page for the service controller ([#197](https://github.com/kubernetes/cloud-provider-aws/pull/197), @nckturner)
* Add self to OWNERS ([#194](https://github.com/kubernetes/cloud-provider-aws/pull/194), @ayberk)
* Fixing broken KEP link ([#193](https://github.com/kubernetes/cloud-provider-aws/pull/193), @pmmalinov01)
* Remove docs publish gh workflow ([#190](https://github.com/kubernetes/cloud-provider-aws/pull/190), @ayberk)
* Fix version ([#189](https://github.com/kubernetes/cloud-provider-aws/pull/189), @ayberk)
* Release v1.20.0-alpha.1 ([#186](https://github.com/kubernetes/cloud-provider-aws/pull/186), @ayberk)

## v1.20.0-alpha.0
* Add release github workflow ([#178](https://github.com/kubernetes/cloud-provider-aws/pull/178), @ayberk)
* Add script to generate changelog ([#179](https://github.com/kubernetes/cloud-provider-aws/pull/179), @ayberk)
* Replace book homepage with README ([#176](https://github.com/kubernetes/cloud-provider-aws/pull/176), @ayberk)
* update klog library from 2.4.0 to 2.5.0 ([#170](https://github.com/kubernetes/cloud-provider-aws/pull/170), @dineshkumar181094)
* Add documentation for cred provider ([#174](https://github.com/kubernetes/cloud-provider-aws/pull/174), @ayberk)
* Add released versions to README ([#175](https://github.com/kubernetes/cloud-provider-aws/pull/175), @nckturner)
* feat: Helm chart for aws cloud controller manager ([#173](https://github.com/kubernetes/cloud-provider-aws/pull/173), @JESWINKNINAN)
* Merge legacy provider ([#160](https://github.com/kubernetes/cloud-provider-aws/pull/160), @nckturner)
* Add wongma7 to owners ([#172](https://github.com/kubernetes/cloud-provider-aws/pull/172), @nckturner)
* tags: initial implementation of tags ([#149](https://github.com/kubernetes/cloud-provider-aws/pull/149), @nicolehanjing)
* Migrate to mkdocs ([#167](https://github.com/kubernetes/cloud-provider-aws/pull/167), @ayberk)
* Update Documentation ([#165](https://github.com/kubernetes/cloud-provider-aws/pull/165), @ayberk)
* Add ECR creds provider ([#157](https://github.com/kubernetes/cloud-provider-aws/pull/157), @ayberk)
* Pass in cloud config file to initialize cloud provider ([#164](https://github.com/kubernetes/cloud-provider-aws/pull/164), @nicolehanjing)
* Bump k8s.io/kubernetes@v1.20.0 ([#151](https://github.com/kubernetes/cloud-provider-aws/pull/151), @nicolehanjing)
* Fix cloudbuild image name ([#163](https://github.com/kubernetes/cloud-provider-aws/pull/163), @nckturner)
* Fix cloudbuild and simplify Makefile & cloudbuild ([#162](https://github.com/kubernetes/cloud-provider-aws/pull/162), @nckturner)
* Add docs publishing script and improve documentation ([#161](https://github.com/kubernetes/cloud-provider-aws/pull/161), @nckturner)
* Fix build command ([#159](https://github.com/kubernetes/cloud-provider-aws/pull/159), @ayberk)
* Makefile target to build and push image for release ([#138](https://github.com/kubernetes/cloud-provider-aws/pull/138), @nckturner)
* add verify-codegen in CI check ([#153](https://github.com/kubernetes/cloud-provider-aws/pull/153), @nicolehanjing)
* Add cloud config for tags ([#152](https://github.com/kubernetes/cloud-provider-aws/pull/152), @nicolehanjing)
* Bump the go version to v1.15 latest ([#150](https://github.com/kubernetes/cloud-provider-aws/pull/150), @nicolehanjing)
* Update go modules to include latest k8s.io/kubernetes module on v-1.19 ([#146](https://github.com/kubernetes/cloud-provider-aws/pull/146), @nicolehanjing)
* Update Flags section of README ([#147](https://github.com/kubernetes/cloud-provider-aws/pull/147), @ayberk)
* instances: initial implementation of instancesV2 interface ([#131](https://github.com/kubernetes/cloud-provider-aws/pull/131), @nicolehanjing)
* latest manifest should point to v1.19.0-alpha.1, not v1.19.1-alpha.1 ([#140](https://github.com/kubernetes/cloud-provider-aws/pull/140), @andrewsykim)
