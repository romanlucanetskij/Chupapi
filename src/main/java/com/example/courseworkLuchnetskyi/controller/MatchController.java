package com.example.courseworkLuchnetskyi.controller;

import com.example.courseworkLuchnetskyi.dto.MatchScheduleDto;
import com.example.courseworkLuchnetskyi.dto.request.MatchRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.MatchResponseDto;
import com.example.courseworkLuchnetskyi.service.MatchService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/api/matches")
@RequiredArgsConstructor
public class MatchController {

    private final MatchService matchService;

    @PostMapping
    public ResponseEntity<MatchResponseDto> createMatch(@RequestBody @Valid MatchRequestDto dto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(matchService.createMatch(dto));
    }

    @GetMapping("/tournament/{tournamentId}")
    public ResponseEntity<List<MatchResponseDto>> getMatchesByTournament(@PathVariable Long tournamentId) {
        return ResponseEntity.ok(matchService.getMatchesByTournament(tournamentId));
    }

    @PutMapping("/{id}")
    public ResponseEntity<MatchResponseDto> updateMatch(@PathVariable Long id,
                                                        @RequestBody @Valid MatchRequestDto dto) {
        return ResponseEntity.ok(matchService.updateMatch(id, dto));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteMatch(@PathVariable Long id) {
        matchService.deleteMatch(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/tournament/{tournamentId}/schedule")
    public List<MatchScheduleDto> getTournamentSchedule(@PathVariable Long tournamentId) {
        return matchService.getTournamentSchedule(tournamentId);
    }
}
