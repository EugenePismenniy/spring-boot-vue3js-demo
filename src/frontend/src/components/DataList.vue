<template>

  <table class="table">
    <thead>
      <tr>
        <th>ID</th>
        <th>Name</th>
        <th>Value</th>
      </tr>
    </thead>

    <tbody>
      <tr v-for="dl in dataList" :key="dl.id">
        <td>{{ dl.id }}</td>
        <td>{{ dl.name }}</td>
        <td>{{ dl.value }}</td>
      </tr>
    </tbody>

  </table>


</template>

<script>
export default {
  name: "data-list",
  props: {
    dataList: {
      type: Array,
      required: true
    }
  }
}
</script>

<style scoped>

</style>