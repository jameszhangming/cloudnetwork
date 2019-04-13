# OVS数据面流表查找

OVS数据面流表查找是网络性能的关键，核心目标是根据SKB报文快速匹配到流表，OVS流表的设计点包括：

* 流表数量不能太多
  * 需要提供流表老化的机制
  * 流表老化后，未匹配到流表采用upcall到用户态来下发流表
* 充分利用硬件能力
  * 使用skb->hash值来进行快速流表匹配
* 报文时间上的连续性
  * 第一次慢匹配，后续快速匹配
* 流表匹配优化
  * 通过连续的内存匹配代替逐个字段的匹配

## 主要数据结构

![flow-object](images/flow-object.png "flow-object")

主要数据类型说明：

* mask_cache_entry
  * per_cpu属性，支持通过skb->hash快速查找mask
* table_instance
  * 存放流表数据
* mask_array
  * 存放mask对象，通过mask和key查找flow


## 流表查找流程

![flow-progress](images/flow-progress.png "flow-progress")

流表查找流程如下：

1. 找到mask_index
  1. 如果skb->hash有值，直接根据该值找到相应的entry，如果通过该entry未查到流表，则从0号开始遍历mask_cache_entry数组（慢查询）
  2. 如果skb->hash未设置，从0号开始遍历mask_cache_entry数组（慢查询）
2. 根据前一步的entry的mask_index成员找到mask，如果通过该mask未找到flow，则会遍历整个mask数组（慢查询）
3. 根据mask和key得到masked_key；
4. 根据masked_key和mask计算出hash；
5. 根据hash值找到bucket，根据bucket找到flow链表；
6. 遍历flow链表，找到匹配的flow（flow->mask等于mask，flow->hash等于hask，flow内容和masked_key相同）
7. 刷新mask_cache_entry数组的mask_index值（下次同类报文可以快速匹配）

### OVS流表查找总结

* mask数量要少
  * mask的数量对流表查找的性能影响非常大，要尽量减少mask的数量
  * mask的数量和流表中使用的字段种类相关，要减少不同报文字段匹配的数量
* 报文进入OVS时全量的key解析有点浪费


## 内核流表更新

![flow-update](images/flow-update.png "flow-update")