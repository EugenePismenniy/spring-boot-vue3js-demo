package ua.demo.springbootvue3jsdemo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ua.demo.springbootvue3jsdemo.domain.DataListItem;

import java.math.BigDecimal;
import java.util.List;

@RestController
@RequestMapping("/api/v1/data-list")
public class DataListController {

    @GetMapping
    public List<DataListItem> getDataListItems() {
        return List.of(
            new DataListItem(1L, "some list item 1", BigDecimal.valueOf(0.2345)),
            new DataListItem(2L, "some list item 2", BigDecimal.valueOf(0.1345)),
            new DataListItem(3L, "some list item 3", BigDecimal.valueOf(0.9345))
        );
    }
}
