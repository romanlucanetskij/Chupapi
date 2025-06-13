package com.example.courseworkLuchnetskyi.dto.response;

import java.time.LocalDate;

public record TournamentResponseDto(
    Long id,
    String name,
    LocalDate startDate,
    LocalDate endDate,
    String location
) {}
