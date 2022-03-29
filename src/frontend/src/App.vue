<template>
  <div class="container">
    <h3>Data List</h3>
    <data-list :data-list="dataList"/>
  </div>
</template>

<script>

import DataList from "@/components/DataList";

export default {
  name: 'App',
  components: {
    DataList
  },
  data() {
    return {
      dataList: [
        {id: 1, name: 'Some name', value: 1234},
        {id: 2, name: 'Some name 2', value: 2234},
        {id: 3, name: 'Some name 3', value: 3234},
      ]
    }
  }
}
</script>

<style>
.container {
  padding: 15px 0;
}
</style>
