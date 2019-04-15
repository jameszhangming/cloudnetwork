# CNM & CNI 

CNM和CNI并不是网络实现，他们是网络规范和网络体系，从研发的角度他们就是一堆接口，你底层是用Flannel也好、用Calico也好，他们并不关心，CNM和CNI关心的是网络管理的问题。

容器网络发展到现在，形成了两大阵营，就是Docker的CNM和Google、CoreOS、Kuberenetes主导的CNI。

## CNM 阵营

Docker Libnetwork的优势就是原生，而且和Docker容器生命周期结合紧密；缺点也可以理解为是原生，被Docker“绑架”：

* Docker Swarm overlay
* Macvlan & IP networkdrivers
* Calico
* Contiv
* Weave
* Kuryr 

## CNI 阵营

CNI的优势是兼容其他容器技术（e.g. rkt）及上层编排系统（Kubernetes & Mesos)，而且社区活跃势头迅猛，Kubernetes加上CoreOS主推；缺点是非Docker原生：

* Kubernetes
* Weave
* Macvlan
* Calico
* Flannel
* Contiv
* Mesos CNI

