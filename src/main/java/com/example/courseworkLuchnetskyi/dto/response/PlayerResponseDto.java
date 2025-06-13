package com.example.courseworkLuchnetskyi.dto.response;

import java.time.LocalDate;

public record PlayerResponseDto(
    Long id,
    String name,
    LocalDate birthDate,
    String position,
    TeamResponseDto team
) {}
