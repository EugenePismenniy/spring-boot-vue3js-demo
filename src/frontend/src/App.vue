<template>
  <div class="container">
    <h3>Data List</h3>
    <data-list :data-list="dataList"/>
  </div>
</template>

<script>

import DataList from "@/components/DataList";

import axios from 'axios'

export default {
  name: 'App',
  components: {
    DataList
  },
  data() {
    return {
      dataList: []
    }
  },
  mounted() {

    axios.get('/api/v1/data-list').then((resp) => {
      this.dataList = resp.data;
    })

  }
}
</script>

<style>
.container {
  padding: 15px 0;
}
</style>
