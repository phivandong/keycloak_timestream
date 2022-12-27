package com.pvdong.horseapimongodb.entity;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;

@Document(collection = "horse")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Horse {
    @Id
    private String id;

    private String name;

    private Date foaled;
}
