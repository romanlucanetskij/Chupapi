package com.example.courseworkLuchnetskyi.dto.request;

import java.time.LocalDate;

public record TournamentRequestDto(
    String name,
    LocalDate startDate,
    LocalDate endDate,
    String location
) {}
