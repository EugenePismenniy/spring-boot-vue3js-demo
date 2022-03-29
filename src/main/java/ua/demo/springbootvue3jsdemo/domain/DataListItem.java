package ua.demo.springbootvue3jsdemo.domain;

import lombok.Value;

import java.math.BigDecimal;


@Value
public class DataListItem {
    Long id;
    String name;
    BigDecimal value;
}
