package com.example.courseworkLuchnetskyi.service;

import com.example.courseworkLuchnetskyi.dto.MatchScheduleDto;
import com.example.courseworkLuchnetskyi.dto.request.MatchRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.MatchResponseDto;

import java.util.List;

public interface MatchService {
    MatchResponseDto createMatch(MatchRequestDto dto);
    List<MatchResponseDto> getMatchesByTournament(Long tournamentId);
    MatchResponseDto updateMatch(Long id, MatchRequestDto dto);
    void deleteMatch(Long id);
    List<MatchScheduleDto> getTournamentSchedule(Long tournamentId);
}
