package com.pvdong.horseapimongodb.dto;

import lombok.Data;

@Data
public class ActivityResponse {
    private String userId;
    private String userName;
    private String activityName;
    private String time;
    private String role;
}
