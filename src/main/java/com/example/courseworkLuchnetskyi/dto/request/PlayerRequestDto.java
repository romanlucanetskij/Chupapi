package com.example.courseworkLuchnetskyi.dto.request;

import java.time.LocalDate;

public record PlayerRequestDto(
    String name,
    LocalDate birthDate,
    String position,
    Long teamId
) {}
