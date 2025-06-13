package com.example.courseworkLuchnetskyi.dto;

import lombok.Data;

@Data
public class TeamAverageAgeDto {
    private Long teamId;
    private String teamName;
    private double averageAge;
}
